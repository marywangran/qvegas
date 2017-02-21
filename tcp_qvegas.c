/*
 * TCP QVegas congestion control
 *
 * This is based on the congestion detection/avoidance scheme described in
 *    Lawrence S. Brakmo and Larry L. Peterson.
 *    "TCP QVegas: End to end congestion avoidance on a global internet."
 *    IEEE Journal on Selected Areas in Communication, 13(8):1465--1480,
 *    October 1995. Available from:
 *	ftp://ftp.cs.arizona.edu/xkernel/Papers/jsac.ps
 *
 * See http://www.cs.arizona.edu/xkernel/ for their implementation.
 * The main aspects that distinguish this implementation from the
 * Arizona QVegas implementation are:
 *   o We do not change the loss detection or recovery mechanisms of
 *     Linux in any way. Linux already recovers from losses quite well,
 *     using fine-grained timers, NewReno, and FACK.
 *   o To avoid the performance penalty imposed by increasing cwnd
 *     only every-other RTT during slow start, we increase during
 *     every RTT during slow start, just like Reno.
 *   o Largely to allow continuous cwnd growth during slow start,
 *     we use the rate at which ACKs come back as the "actual"
 *     rate, rather than the rate at which data is sent.
 *   o To speed convergence to the right rate, we set the cwnd
 *     to achieve the right ("actual") rate when we exit slow start.
 *   o To filter out the noise caused by delayed ACKs, we use the
 *     minimum RTT sample observed during the last RTT to calculate
 *     the actual rate.
 *   o When the sender re-starts from idle, it waits until it has
 *     received ACKs for an entire flight of new data before making
 *     a cwnd adjustment decision. The original QVegas implementation
 *     assumed senders never went idle.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>

#include <net/tcp.h>

//#include "tcp_qvegas.h"

/* Vegas variables */
struct qvegas {
	u32	beg_snd_nxt;	/* right edge during last RTT */
	u32	beg_snd_una;	/* left edge  during last RTT */
	u32	beg_snd_cwnd;	/* saves the size of the cwnd */
	u32	lost_cwnd;	/* saves the size of the cwnd */
	u32	reno_inc;
	u8	doing_qvegas_now;/* if true, do qvegas for this RTT */
	u16	cntRTT;		/* # of RTTs measured within last RTT */
	u32	minRTT;		/* min of RTTs measured within last RTT (in usec) */
	u32	baseRTT;	/* the min of all Vegas RTT measurements seen (in usec) */
};

static int alpha = 2;
static int beta  = 4;
static int gamma = 1;

module_param(alpha, int, 0644);
MODULE_PARM_DESC(alpha, "lower bound of packets in network");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "upper bound of packets in network");
module_param(gamma, int, 0644);
MODULE_PARM_DESC(gamma, "limit on increase (scale by 2)");

/* There are several situations when we must "re-start" QVegas:
 *
 *  o when a connection is established
 *  o after an RTO
 *  o after fast recovery
 *  o when we send a packet and there is no outstanding
 *    unacknowledged data (restarting an idle connection)
 *
 * In these circumstances we cannot do a QVegas calculation at the
 * end of the first RTT, because any calculation we do is using
 * stale info -- both the saved cwnd and congestion feedback are
 * stale.
 *
 * Instead we must wait until the completion of an RTT during
 * which we actually receive ACKs.
 */
static void qvegas_enable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct qvegas *qvegas = inet_csk_ca(sk);

	/* Begin taking QVegas samples next time we send something. */
	qvegas->doing_qvegas_now = 1;

	/* Set the beginning of the next send window. */
	qvegas->beg_snd_nxt = tp->snd_nxt;

	qvegas->cntRTT = 0;
	qvegas->reno_inc = 0;
	qvegas->minRTT = 0x7fffffff;
}

/* Stop taking QVegas samples for now. */
static inline void qvegas_disable(struct sock *sk)
{
	struct qvegas *qvegas = inet_csk_ca(sk);

	qvegas->doing_qvegas_now = 0;
}

void tcp_qvegas_init(struct sock *sk)
{
	struct qvegas *qvegas = inet_csk_ca(sk);
	
	if (qvegas->baseRTT == 0)
		qvegas->lost_cwnd = TCP_INIT_CWND; 
	qvegas->baseRTT = 0x7fffffff;
	qvegas_enable(sk);
}
EXPORT_SYMBOL_GPL(tcp_qvegas_init);

/* Do RTT sampling needed for QVegas.
 * Basically we:
 *   o min-filter RTT samples from within an RTT to get the current
 *     propagation delay + queuing delay (we are min-filtering to try to
 *     avoid the effects of delayed ACKs)
 *   o min-filter RTT samples from a much longer window (forever for now)
 *     to find the propagation delay (baseRTT)
 */
void tcp_qvegas_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct qvegas *qvegas = inet_csk_ca(sk);
	u32 vrtt;

	if (sample->rtt_us < 0)
		return;

	/* Never allow zero rtt or baseRTT */
	vrtt = sample->rtt_us + 1;

	/* Filter to find propagation delay: */
	if (vrtt < qvegas->baseRTT)
		qvegas->baseRTT = vrtt;

	/* Find the min RTT during the last RTT to find
	 * the current prop. delay + queuing delay:
	 */
	qvegas->minRTT = min(qvegas->minRTT, vrtt);
	qvegas->cntRTT++;
}
EXPORT_SYMBOL_GPL(tcp_qvegas_pkts_acked);

u32 qvegas_undo_cwnd(struct sock *sk)
{
	struct qvegas *qvegas = inet_csk_ca(sk);

	return max(qvegas->lost_cwnd, 2U);
}

void tcp_qvegas_state(struct sock *sk, u8 ca_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct qvegas *qvegas = inet_csk_ca(sk);

	if (ca_state == TCP_CA_Open) {
		qvegas_enable(sk);
		tp->snd_cwnd = max(qvegas->lost_cwnd, 2U);
	} else {
		qvegas_disable(sk);
	}
}
EXPORT_SYMBOL_GPL(tcp_qvegas_state);

/*
 * If the connection is idle and we are restarting,
 * then we don't want to do any QVegas calculations
 * until we get fresh RTT samples.  So when we
 * restart, we reset our QVegas state to a clean
 * slate. After we get acks for this flight of
 * packets, _then_ we can make QVegas calculations
 * again.
 */
void tcp_qvegas_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_CWND_RESTART ||
	    event == CA_EVENT_TX_START)
		tcp_qvegas_init(sk);
}
EXPORT_SYMBOL_GPL(tcp_qvegas_cwnd_event);

static inline u32 tcp_qvegas_ssthresh(struct tcp_sock *tp)
{
	struct sock *sk = (struct sock *)tp;
	struct qvegas *qvegas = inet_csk_ca(sk);

	if (tp->lost_out)
		qvegas->lost_cwnd = max(tp->snd_cwnd - qvegas->reno_inc>>1U, 2U);
	return  max(min(tp->snd_ssthresh, tp->snd_cwnd-1), 2U);
}

static void tcp_qvegas_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct qvegas *qvegas = inet_csk_ca(sk);

	if (!qvegas->doing_qvegas_now) {
		u32 cwnd = tp->snd_cwnd;
		tcp_reno_cong_avoid(sk, ack, acked);
		qvegas->reno_inc += tp->snd_cwnd - cwnd;
		return;
	}

	if (after(ack, qvegas->beg_snd_nxt)) {
		/* Do the QVegas once-per-RTT cwnd adjustment. */

		/* Save the extent of the current window so we can use this
		 * at the end of the next RTT.
		 */
		tp->snd_cwnd = qvegas->lost_cwnd;
		qvegas->beg_snd_nxt  = tp->snd_nxt;

		/* We do the QVegas calculations only if we got enough RTT
		 * samples that we can be reasonably sure that we got
		 * at least one RTT sample that wasn't from a delayed ACK.
		 * If we only had 2 samples total,
		 * then that means we're getting only 1 ACK per RTT, which
		 * means they're almost certainly delayed ACKs.
		 * If  we have 3 samples, we should be OK.
		 */

		if (qvegas->cntRTT <= 2) {
			u32 cwnd = tp->snd_cwnd;
			tcp_reno_cong_avoid(sk, ack, acked);
			qvegas->reno_inc += tp->snd_cwnd - cwnd;
		} else  {
			u32 rtt, diff;
			u64 target_cwnd;//, tg;

			/* We have enough RTT samples, so, using the QVegas
			 * algorithm, we determine if we should increase or
			 * decrease cwnd, and by how much.
			 */

			/* Pluck out the RTT we are using for the QVegas
			 * calculations. This is the min RTT seen during the
			 * last RTT. Taking the min filters out the effects
			 * of delayed ACKs, at the cost of noticing congestion
			 * a bit later.
			 */
			rtt = qvegas->minRTT;

			/* Calculate the cwnd we should have, if we weren't
			 * going too fast.
			 *
			 * This is:
			 *     (actual rate in segments) * baseRTT
			 */
			target_cwnd = (u64)tp->snd_cwnd * qvegas->baseRTT;
			do_div(target_cwnd, rtt);

			/* Calculate the difference between the window we had,
			 * and the window we would like to have. This quantity
			 * is the "Diff" from the Arizona QVegas papers.
			 */
			diff = tp->snd_cwnd * (rtt-qvegas->baseRTT) / qvegas->baseRTT;

			if (diff > gamma && tcp_in_slow_start(tp)) {
				/* Going too fast. Time to slow down
				 * and switch to congestion avoidance.
				 */

				/* Set cwnd to match the actual rate
				 * exactly:
				 *   cwnd = (actual rate) * baseRTT
				 * Then we add 1 because the integer
				 * truncation robs us of full link
				 * utilization.
				 */
				tp->snd_cwnd = min(tp->snd_cwnd, (u32)target_cwnd+1);
				tp->snd_ssthresh = tcp_qvegas_ssthresh(tp);

			} else if (tcp_in_slow_start(tp)) {
				/* Slow start.  */
				tcp_slow_start(tp, acked);
			} else {
				/* Congestion avoidance. */

				/* Figure out where we would like cwnd
				 * to be.
				 */
				if (diff > beta) {
					/* The old window was too fast, so
					 * we slow down.
					 */
					tp->snd_cwnd --;
					tp->snd_ssthresh
						= tcp_qvegas_ssthresh(tp);
				} else if (diff < alpha) {
					/* We don't have enough extra packets
					 * in the network, so speed up.
					 */
					tp->snd_cwnd ++;
				} else {
					/* Sending just as fast as we
					 * should be.
					 */
				}
			}

			if (tp->snd_cwnd < 4)
				tp->snd_cwnd = 4;
			else if (tp->snd_cwnd > tp->snd_cwnd_clamp)
				tp->snd_cwnd = tp->snd_cwnd_clamp;

			tp->snd_ssthresh = tcp_current_ssthresh(sk);
		}

		/* Wipe the slate clean for the next RTT. */
		qvegas->cntRTT = 0;
		qvegas->minRTT = 0x7fffffff;
		qvegas->lost_cwnd = tp->snd_cwnd;
	}
	/* Use normal slow start */
	else if (tcp_in_slow_start(tp)) {
		tcp_slow_start(tp, acked);
	}
}

/* Extract info for Tcp socket info provided via netlink. */
size_t tcp_qvegas_get_info(struct sock *sk, u32 ext, int *attr,
			  union tcp_cc_info *info)
{
/*
	const struct qvegas *ca = inet_csk_ca(sk);
	if (ext & (1 << (INET_DIAG_QVEGASINFO - 1))) {
		info->qvegas.tcpv_enabled = ca->doing_qvegas_now,
		info->qvegas.tcpv_rttcnt = ca->cntRTT,
		info->qvegas.tcpv_rtt = ca->baseRTT,
		info->qvegas.tcpv_minrtt = ca->minRTT,

		*attr = INET_DIAG_QVEGASINFO;
		return sizeof(struct tcpqvegas_info);
	}
*/
	return 0;
}
EXPORT_SYMBOL_GPL(tcp_qvegas_get_info);

static struct tcp_congestion_ops tcp_qvegas __read_mostly = {
	.init		= tcp_qvegas_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_qvegas_cong_avoid,
	.pkts_acked	= tcp_qvegas_pkts_acked,
	.set_state	= tcp_qvegas_state,
	.cwnd_event	= tcp_qvegas_cwnd_event,
	.undo_cwnd	= qvegas_undo_cwnd,
	.get_info	= tcp_qvegas_get_info,

	.owner		= THIS_MODULE,
	.name		= "qvegas",
};

static int __init tcp_qvegas_register(void)
{
	BUILD_BUG_ON(sizeof(struct qvegas) > ICSK_CA_PRIV_SIZE);
	tcp_register_congestion_control(&tcp_qvegas);
	return 0;
}

static void __exit tcp_qvegas_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_qvegas);
}

module_init(tcp_qvegas_register);
module_exit(tcp_qvegas_unregister);

MODULE_AUTHOR("Stephen Hemminger & me");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP QVegas");
