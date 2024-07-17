# O-RAN-SC IsO-RAN xApp in Golang

## About this project

Final project of Advanced Topics in Computer & Network Security (ATCNS), at the University of Padova. Here, we're dealing with the Near-RT RIC platform and its interconnection with the Non-RT RIC platform. The developed xApp was built starting from the [hw-go](https://gerrit.o-ran-sc.org/r/admin/repos/ric-app/hw-go) repository available on Gerrit.

The primary objective was to exploit a vulnerability in the RMR (RIC Message Router) library, specifically associated with route tables. The vulnerability arises from the lack of authentication in the route tables sent into O-RAN SC platform using the xApp. By analyzing the overall route table sent by the route manager, we crafted raw packets (can be found in `rmr_payloads`) designed to disrupt the connection between the Near-RT RIC module and all its external interfaces. As a result, we isolated the Near-RT RIC module from the rest of the RAN. The idea of this attack was inspired by the following [paper](https://ieeexplore.ieee.org/abstract/document/10338835). 

To understand and execute the attack, please refer to the following [Gist](https://gist.github.com/werefin/f49489677c1e5bc8d92e7a4c37d033e9) repository. The latter contains detailed instructions and the necessary scripts for replicating the attack on the RMR library vulnerability. repository from gerrit. The idea was to exploit a vulnerability in the RMR library associated to route tables in particular.

## IsO-RAN attack results

Now we will see the steps that led to achieving the previously mentioned objective. It is essential to specify that we will refer to the **O-RAN SC H-release** version. Initially, we can see the routing table just after deploying the malicious xApp with the insertion of the routes associated with it. Additionally, all the Kubernetes pods associated with `ricplt` are in a running state, and the gNB associated with the E2 node is connected to the RAN (via E2 termination).

![rt_before_attack](https://github.com/user-attachments/assets/2d41d61d-f057-4943-9f42-cab92af1213a)

The attack starts after about 40 seconds, giving the RMR library enough time to initialize. As seen from the xApp logs below, first the `rmr_empty_rt.raw` packet is sent, causing the E2 termination to crash, and immediately after, a DoS attack is launched against the A1 mediator.

![xapp_logs_1](https://github.com/user-attachments/assets/1f2066ba-e558-4da0-bda7-b7cd4af18dd6)

![xapp_logs_2](https://github.com/user-attachments/assets/5eb4effe-ab6d-4fdd-b882-f8d9431a7353)

Below we can see the results obtained regarding the crashed Kubernetes pods after the attack. In particular, since A1 and E2 are the only terminations interconnecting the Near-RT RIC module with the outside, the latter remains isolated from the rest of the O-RAN components (e.g., Non-RT RIC).

![screenshot_after_attack_1](https://github.com/user-attachments/assets/c476b84f-2fdf-4b61-9df0-95a67f835a28)

![screenshot_after_attack_2](https://github.com/user-attachments/assets/0b640a99-c191-4f6f-8938-56a125dcecd5)

Indeed, as seen below and as previously specified, the exploit mainly affects the routing table, which theoretically the xApp should not be able to modify. However, due to a lack of authentication, the attack triggers an update of the routing table in which no gNB is connected via E2 termination. The DoS approach towards the A1 is different; in this case, it is not an issue associated with the routing tables being modified towards the A1 mediator, but rather, the component accepts raw packets sent by the xApp, causing a `CrashLoopBackOff` on its Kubernetes pod.

![rt_after_attack](https://github.com/user-attachments/assets/acad7283-73b6-41a7-adb6-2f80ba75412c)

In conclusion, even when attempting to reconnect the E2 simulator (`kpm_sim`) to the O-RAN, the connection status remains `UNDER_RESET`; this implies that the network is compromised until a new installation of the `ricplt` is performed.

![sceenshot_after_attack_3](https://github.com/user-attachments/assets/33dc67ac-be3c-49f7-b440-db512e593be8)

![screenshot_after_attack_4](https://github.com/user-attachments/assets/a3bed4ea-bcee-4c19-9e52-783f382134e9)
