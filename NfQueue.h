#ifndef NFQUEUE_H
#define NFQUEUE_H 1


struct WfConfig;
struct NfQueue;

void NfQueue_put(struct NfQueue **nfq_wf);

struct NfQueue* NfQueue_new(int q_id, struct WfConfig *config);

int NfQueue_updateConfig(struct NfQueue *nfqp, struct WfConfig *config);

int NfQueue_start(struct NfQueue* nfq_wf);

int NfQueue_stop(struct NfQueue* nfq_wf);

int NfQueue_join(struct NfQueue* nfq_wf);

#endif
