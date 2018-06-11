
# HAProxy Opspack

HAProxy is a free tool offering high availability, load balancing, and proxying for TCP and HTTP-based applications. Well-suited for high traffic websites, HAProxy has become the industry standard open-source load balancer and is often shipped with most mainstream Linux distributions as well as commonly deployed by default in cloud platforms.

Its mode of operation makes integration into existing architectures quite simple and keeps security top of mind, ensuring that valuable web servers with private information are not exposed.  

## Service Checks

| Service Check | Description |
|:------------- |:----------- |
| session_conn | The number of accepted connections |
|client_req | The number of client requests received |
|session_dropped | Checking varnish cache dropped sessions |
|cache_hit | Checking the number of cache hits |
|cache_hitpass | Checks hits for pass |
|expired_objects | The total number of expired objects |
|threads | The total number of threads |
|threads_limited | Times the number of threads hit the maximum |
|session_queued | Number of sessions queued |
|backend_connections | Number of connections to the backend |
|backend_recycle | Number of recycled conections |
|backend_reuse | Number of reused connections |
|backend_fail | Number of failed connections |
|backend_unhealthy | Number of unhealthy connections |
|backend_busy | Number of busy connections |
|backend_req | Number of backend requests |
|backend_retry | Number of retried connections |

## Setup and Configuration

HAProxy has been tested against version 1.5, 1.6 and 1.7. If you are running HAProxy version 1.5 or 1.6 three service checks will need to be deactivated as the metrics are not available for those versions. The service checks that need to be stopped are denied connections, denied sessions and intercepted requests.

**Setting up HAProxy for monitoring:**

To configure HAProxy, you need to set up a statistics page on the server. This can be done by editing haproxy.cfg the default location of the file is /etc/haproxy/haproxy.cfg, and this needs changing by running this command with your preferred editor. Then add the lines below to the file for each proxy if the stats haven't been set up already.
```
listen stats
          bind <Your haproxy IP>:<Port>
          mode http
          stats enable
          stats hide-version
          stats realm haproxy\ Statistics
          stats uri /haproxy?stats
          stats auth <Username>:<Password>
```

restart HAProxy with the command `sudo service haproxy restart`.
To test if the stats are running correctly, open a web browser and enter `http://<Your haproxyIP>:<Port>/haproxy?stats` and then view the statistics.

**Setup and configuration:**
To configure and utilize this Opspack, you simply need to add the 'Application - Haproxy' Opspack to the host running the HAProxy software, and specify the HAProxy user name, password, port and the stats URI path via the variable 'HAPROXY'. HaProxy creates new service checks for each proxy set up via the variable 'HAPROXY_PROXY'.

Step 1: Add the host template
![Add host template](/docs/img/host-template.png?raw=true)

Step 2: Add and configure the HAPROXY and HAPROXY_PROXY variables
![Add variables](/docs/img/variables.png?raw=true)
![Add variables 2](/docs/img/variables2.png?raw=true)

Step 3: Reload and view the HAProxy statistics
![Service checks](/docs/img/output.png?raw=true)
