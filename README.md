# openwrt-ssrsub

## shadowsocksr subscriber  
Download decode and update shadowsocksr config for your device, this program is suitable for shadowsocks-libev  
(https://github.com/shadowsocks/openwrt-shadowsocks.git)

Usage:  
 -f \<filepath\>        Target ssr subscribe file to be decode, this function is aimed at  
                        resolving files that manually download subscribe file from server  
                        and manually upload to your device. This param and "-u " is alternative.  
                        
 -u \<subscribe URL\>   Target ssr subscribe URL for processing,   
                        this param and "-f " is alternative.  
                        
 -d \<dns server\>      The dns server for host name resolving, this dns server must be  
                        reliable, otherwise the resolved host IP will be invalid.  

 -x                     Use this argument the program will delete temp files after finished.  

 -c                     Use this argument the program will delete all the ssr server config.  


## openwrt-shadowsocksr的服务器订阅程序  
该程序用于下载、解析shadowsocksr服务器订阅文件，解析结果将会被添加到shadowsocksr的可用服务器列表，方便了openwrt-shadowsocksr的服务器列表更新过程。  

使用方法：  

 -f \<filepath\>        指定一个本地的订阅文件以备解析，该功能的目的是当在线更新出现故障时，通过  
                        其他渠道下载订阅文件，上传到路由器，然后进行解析。这个参数和"-u"是二选一的。  

 -u \<subscribe URL\>   指定订阅链接，该功能通过指定的链接自动下载订阅文件并解析。  
                        这个参数和"-f"是二选一的。  
                      
 -d \<dns server\>      指定用于域名解析的dns服务器，必须是可靠的dns服务器，  
                        否则解析结果可能是无效的。  

 -x                     该参数用于订阅后清除下载的订阅文件  

 -c                     该参数用于删除所有之前的ssr服务器配置  
