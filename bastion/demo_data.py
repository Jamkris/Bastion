"""데모 모드용 샘플 출력. BASTION_DEMO=true면 collectors가 실제 명령 대신
이 데이터를 반환한다. 리눅스 명령이 없는 개발 환경(맥) 미리보기 + 공개 데모용."""

FAIL2BAN_STATUS = """Status
|- Number of jail:      1
`- Jail list:   sshd
"""

FAIL2BAN_STATUS_SSHD = """Status for the jail: sshd
|- Filter
|  |- Currently failed: 9
|  |- Total failed:     41416
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 12
   |- Total banned:     12
   `- Banned IP list:   1.222.42.237 101.126.54.36 102.208.34.7 103.113.105.228 45.148.10.183 92.118.39.195 218.145.181.48 121.165.187.77 61.156.218.5 190.0.63.226 45.156.87.182 218.157.205.238
"""

SS_TLNP = """State           Recv-Q          Send-Q                   Local Address:Port                    Peer Address:Port          Process
LISTEN          0               128                          127.0.0.1:631                          0.0.0.0:*
LISTEN          0               4096                           0.0.0.0:8480                         0.0.0.0:*
LISTEN          0               511                            0.0.0.0:3017                         0.0.0.0:*              users:(("node /home/jamk",pid=895,fd=20))
LISTEN          0               128                            0.0.0.0:22                           0.0.0.0:*
LISTEN          0               4096                           0.0.0.0:53                           0.0.0.0:*
LISTEN          0               4096                                 *:9090                               *:*
LISTEN          0               4096                              [::]:443                             [::]:*
LISTEN          0               128                               [::]:22                              [::]:*
"""

NFT_RULESET = (
    '{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}, '
    '{"table": {"family": "inet", "name": "f2b-table", "handle": 1}}, '
    '{"chain": {"family": "inet", "table": "f2b-table", "name": "f2b-chain", "handle": 1, '
    '"type": "filter", "hook": "input", "prio": -1, "policy": "accept"}}, '
    '{"set": {"family": "inet", "name": "addr-set-sshd", "table": "f2b-table", '
    '"type": "ipv4_addr", "handle": 2, "elem": ["1.222.42.237", "101.126.54.36", "102.208.34.7"]}}, '
    '{"rule": {"family": "inet", "table": "f2b-table", "chain": "f2b-chain", "handle": 3, '
    '"expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, '
    '"right": 22}}, {"match": {"op": "in", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, '
    '"right": "@addr-set-sshd"}}, {"drop": null}]}}]}'
)

AUTH_LOG = """Jul  9 10:01:02 server1 sshd[1111]: Failed password for root from 1.222.42.237 port 51000 ssh2
Jul  9 10:01:05 server1 sshd[1112]: Failed password for root from 1.222.42.237 port 51002 ssh2
Jul  9 10:01:20 server1 sshd[1120]: Failed password for root from 1.222.42.237 port 51020 ssh2
Jul  9 10:01:09 server1 sshd[1113]: Invalid user admin from 101.126.54.36 port 40000
Jul  9 10:01:12 server1 sshd[1114]: Failed password for invalid user admin from 101.126.54.36 port 40002 ssh2
Jul  9 10:02:30 server1 sshd[1116]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=102.208.34.7
Jul  9 10:03:41 server1 sshd[1130]: Failed password for root from 45.148.10.183 port 33000 ssh2
Jul  9 10:03:44 server1 sshd[1131]: Failed password for root from 45.148.10.183 port 33002 ssh2
"""
