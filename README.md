# O-RAN-SC IsO-RAN xApp in Golang

Final project of Advanced Topics in Computer & Network Security (ATCNS), at the University of Padova. Here, we're dealing with the Near-RT RIC platform and its interconnection with the Non-RT RIC platform. The developed xApp was built starting from the [hw-go](https://gerrit.o-ran-sc.org/r/admin/repos/ric-app/hw-go) repository available on Gerrit.

The primary objective was to exploit a vulnerability in the RMR (RIC Message Router) library, specifically associated with route tables. The vulnerability arises from the lack of authentication in the route tables sent into O-RAN SC platform using the xApp. By analyzing the overall route table sent by the route manager, we crafted raw packets (can be found in `rmr_payloads`) designed to disrupt the connection between the Near-RT RIC module and all its external interfaces. As a result, we isolated the Near-RT RIC module from the rest of the RAN. The idea of this attack was inspired by the following [paper](https://ieeexplore.ieee.org/abstract/document/10338835).

To understand and execute the attack, please refer to the following [gist](https://gist.github.com/werefin/f49489677c1e5bc8d92e7a4c37d033e9) repository. The latter contains detailed instructions and the necessary scripts for replicating the attack on the RMR library vulnerability. repository from gerrit. The idea was to exploit a vulnerability in the RMR library associated to route tables in particular.

## IsO-RAN attack results

RMR route table before the attack:

![rt_before_attack](https://github.com/user-attachments/assets/e04c6d23-1849-46dc-808e-1b4fd94be082)

xApp logs:

![xapp_logs_1](https://github.com/user-attachments/assets/1f2066ba-e558-4da0-bda7-b7cd4af18dd6)

![xapp_logs_2](https://github.com/user-attachments/assets/5eb4effe-ab6d-4fdd-b882-f8d9431a7353)

Kubernetes pods after the attack:

![screenshot_after_attack_1](https://github.com/user-attachments/assets/c476b84f-2fdf-4b61-9df0-95a67f835a28)

![screenshot_after_attack_2](https://github.com/user-attachments/assets/0b640a99-c191-4f6f-8938-56a125dcecd5)

RMR route table after the attack:

![rt_after_attack](https://github.com/user-attachments/assets/146474fe-fd13-4284-a2e3-068ccb33ace2)

Trying to reconnect trough E2 sim:

![sceenshot_after_attack_3](https://github.com/user-attachments/assets/33dc67ac-be3c-49f7-b440-db512e593be8)

![screenshot_after_attack_4](https://github.com/user-attachments/assets/a3bed4ea-bcee-4c19-9e52-783f382134e9)
