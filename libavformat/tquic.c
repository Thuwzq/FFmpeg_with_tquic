#include "libavutil/avstring.h"
#include "libavutil/opt.h"
#include "avformat.h"
#include "network.h"
#include "url.h"
#include "libavutil/parseutils.h"
#include "libavutil/mem.h"
#include "third_party/tquic/include/tquic.h"  // TQUIC header file
#include "libavutil/error.h"

#include <ev.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

// Simplified platform detection - only supports Unix-like systems
#if defined(__APPLE__) && defined(__MACH__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IPHONE
        #define PLATFORM_IOS 1
    #elif TARGET_OS_MAC
        #define PLATFORM_MACOS 1
    #endif
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
#else
    #define PLATFORM_UNKNOWN 1
#endif

#define MAX_TQUIC_DATAGRAM_SIZE 1200
#define READ_BUF_SIZE 4096

typedef struct TQUICContext {
    const AVClass *class;
    quic_endpoint_t *quic_endpoint;
    quic_tls_config_t *tls_config;
    int socket_fd;
    quic_conn_t *quic_conn; 
    uint64_t quic_stream_id;
    quic_config_t *tquic_config;

    struct ev_loop *loop;
    ev_timer timer;

    //remote address and port
    char *remote_addr;
    char *remote_port;
    struct addrinfo *peer;

    //local address and port
    char *local_addr;
    char *local_port;
    struct addrinfo *local;
    int use_wifi_flag;  // 1=use wifi address, 0=use cellular address
    char wifi_addr[INET_ADDRSTRLEN];   // wifi interface IP address
    char cellular_addr[INET_ADDRSTRLEN]; // cellular interface IP address

    //if finish download file
    bool fin_flag;
    bool read_ready_flag;

    //request context
    char path[1024];

    //tquic ev_loop thread
    pthread_t receive_thread;

    // Mutex for thread safety
    pthread_mutex_t read_write_mutex;

} TQUICContext;

static const AVOption tquic_options[] = {
    { "use_wifi", "use wifi(1) or cellular(0)", offsetof(TQUICContext, use_wifi_flag), AV_OPT_TYPE_INT, { .i64 = 1 }, 0, 1, AV_OPT_FLAG_DECODING_PARAM },
    { NULL }
};

// 协议类定义
static const AVClass tquic_class = {
    .class_name = "tquic",
    .item_name  = av_default_item_name,
    .option     = tquic_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

static void process_connections(URLContext *h) {
    TQUICContext *s = h->priv_data;
    double timeout;

    av_log(h, AV_LOG_DEBUG, "TQUIC connection process\n");
    pthread_mutex_lock(&s->read_write_mutex);
    quic_endpoint_process_connections(s->quic_endpoint);
    timeout = quic_endpoint_timeout(s->quic_endpoint) / 1e3f;
    pthread_mutex_unlock(&s->read_write_mutex);
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    s->timer.repeat = timeout;
    ev_timer_again(s->loop, &s->timer);
}

// ev read event callback
static void read_callback(EV_P_ ev_io *w, int revents) {
    URLContext *h = w->data;
    TQUICContext *s = h->priv_data;
    static uint8_t buf[READ_BUF_SIZE];

    av_log(h, AV_LOG_DEBUG, "TQUIC socket read callback start\n");
    pthread_mutex_lock(&s->read_write_mutex);
    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        ssize_t read;
        int ret;

        quic_packet_info_t quic_packet_info;
        memset(&peer_addr, 0, peer_addr_len);

        read = recvfrom(s->socket_fd, buf, READ_BUF_SIZE, 0, (struct sockaddr *)&peer_addr, &peer_addr_len);

        if (read < 0){
            if((errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            
            av_log(h, AV_LOG_ERROR, "tquic: read packet from socket error.\n");
            return;
        }

        quic_packet_info = (quic_packet_info_t){
            .src = (struct sockaddr *)&peer_addr,
            .src_len = peer_addr_len,
            .dst = s->local->ai_addr,
            .dst_len = s->local->ai_addrlen,
        };

        
        av_log(h, AV_LOG_DEBUG, "tquic: endpoint recv packet.\n");
        ret = quic_endpoint_recv(s->quic_endpoint, buf, read, &quic_packet_info);

        if (ret != 0){
            av_log(h, AV_LOG_ERROR, "tquic: endpoint fail recv packet.\n");
            continue;
        }
    }
    pthread_mutex_unlock(&s->read_write_mutex);
    process_connections(h);
    av_log(h, AV_LOG_DEBUG, "TQUIC socket read callback finish\n");
}

static void* event_loop_thread(void* arg){
    URLContext *h = (URLContext *)arg;
    TQUICContext *s = h->priv_data;
    
    ev_io watcher;
    ev_io_init(&watcher, read_callback, s->socket_fd, EV_READ);
    ev_io_start(s->loop, &watcher);
    watcher.data = h;
    ev_loop(s->loop, 0);

    return NULL;
}

// 回调函数实现
static void tquic_on_conn_created(void *tctx, struct quic_conn_t *conn)
{
    URLContext *ctx = tctx;
    av_log(ctx, AV_LOG_INFO, "TQUIC connection created\n");
}

static void tquic_on_conn_established(void *tctx, struct quic_conn_t *conn)
{
    URLContext *h = tctx;
    TQUICContext *s = h->priv_data;

    int ret;
    av_log(h, AV_LOG_INFO, "TQUIC connection established\n");
    
    s->quic_conn = conn;

    //Get TQUIC stream
    ret = quic_stream_bidi_new(s->quic_conn, 0, false, &s->quic_stream_id);
    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "tquic: cannot create stream, ret = %d\n", ret);
        goto fail;
    }
    av_log(h, AV_LOG_INFO, "conn_established: TQUIC stream has created\n");

    return;
    
fail:

    if (s->peer != NULL){
        freeaddrinfo(s->peer);
    }

    if (s->tls_config != NULL) {
        quic_tls_config_free(s->tls_config);
    }

    if (s->socket_fd > 0){
        close(s->socket_fd);
    }

    if (s->quic_endpoint != NULL) {
        quic_endpoint_free(s->quic_endpoint);
    }

    if (s->loop != NULL) {
        ev_loop_destroy(s->loop);
    }

    if (s->tquic_config != NULL) {
        quic_config_free(s->tquic_config);
    }
    return;
}

static void tquic_on_conn_closed(void *tctx, struct quic_conn_t *conn)
{
    URLContext *ctx = tctx;
    av_log(ctx, AV_LOG_INFO, "TQUIC connection closed\n");
}

static void tquic_on_stream_created(void *tctx, struct quic_conn_t *conn, uint64_t stream_id) 
{
    URLContext *ctx = tctx;
    TQUICContext *s = ctx->priv_data;

    char request_data[1024];
    int ret;

    av_log(ctx, AV_LOG_INFO, "TQUIC stream created, stream id: %llu\n", stream_id);

    //start http0.9 request
    sprintf(request_data, "GET %s\r\n", s->path);
    av_log(ctx, AV_LOG_INFO, "request: %s\n", request_data);
    ret = (int)quic_stream_write(s->quic_conn, s->quic_stream_id, (uint8_t*)request_data, strlen(request_data), true);
    if (ret < 0) {
        av_log(ctx, AV_LOG_ERROR, "tquic: cannot write request, ret = %d\n", ret);
        goto fail;
    }

    return;
    
fail:

    if (s->peer != NULL){
        freeaddrinfo(s->peer);
    }
    
    if (s->tls_config != NULL) {
        quic_tls_config_free(s->tls_config);
    }
    
    if (s->socket_fd > 0){
        close(s->socket_fd);
    }
    
    if (s->quic_endpoint != NULL) {
        quic_endpoint_free(s->quic_endpoint);
    }
    
    if (s->loop != NULL) {
        ev_loop_destroy(s->loop);
    }
    
    if (s->tquic_config != NULL) {
        quic_config_free(s->tquic_config);
    }
    return;
}

static void tquic_on_stream_readable(void *tctx, struct quic_conn_t *conn, uint64_t stream_id) 
{
    URLContext *ctx = tctx;
    TQUICContext *s = ctx->priv_data;
    // av_log(ctx, AV_LOG_INFO, "TQUIC stream readable, stream id: %llu\n", stream_id);

    if (s->quic_stream_id == stream_id){
        s->read_ready_flag = true;
    } 
}

static void tquic_on_stream_writable(void *tctx, struct quic_conn_t *conn, uint64_t stream_id) 
{
    URLContext *ctx = tctx;
    av_log(ctx, AV_LOG_INFO, "TQUIC stream writable, stream id: %llu\n", stream_id);
}

static void tquic_on_stream_closed(void *tctx, struct quic_conn_t *conn, uint64_t stream_id) 
{
    URLContext *ctx = tctx;
    av_log(ctx, AV_LOG_INFO, "TQUIC stream closed, stream id: %llu\n", stream_id);
}

static int tquic_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts, unsigned int count) 
{
    URLContext *ctx = psctx;
    TQUICContext *s = ctx->priv_data;
    unsigned int sent_count = 0;
    
    int i, j = 0;
    // av_log(ctx, AV_LOG_INFO, "TQUIC data ready to send, count: %d\n", count);
    for (i = 0; i < count; i++) {
        struct quic_packet_out_spec_t *pkt = pkts + i;
        for (j = 0; j < (*pkt).iovlen; j++) {
            const struct iovec *iov = pkt->iov + j;
            ssize_t sent =
                sendto(s->socket_fd, iov->iov_base, iov->iov_len, 0,
                       (struct sockaddr *)pkt->dst_addr, pkt->dst_addr_len);
            // av_log(ctx, AV_LOG_INFO, "TQUIC data sent, size: %zd\n", sent);

            if (sent != iov->iov_len) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    av_log(ctx, AV_LOG_ERROR, "send would block, already sent: %d\n",
                            sent_count);
                    return sent_count;
                }
                return -1;
            }
            sent_count++;
        }
    }

    return sent_count;
}

const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created = tquic_on_conn_created,
    .on_conn_established = tquic_on_conn_established,
    .on_conn_closed = tquic_on_conn_closed,
    .on_stream_created = tquic_on_stream_created,
    .on_stream_readable = tquic_on_stream_readable,
    .on_stream_writable = tquic_on_stream_writable,
    .on_stream_closed = tquic_on_stream_closed,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = tquic_on_packets_send,
};

static void timeout_callback(EV_P_ ev_timer *w, int revents) {
    URLContext *h = w->data;
    TQUICContext *ctx = h->priv_data;
    // av_log(h, AV_LOG_INFO, "TQUIC timeout callback\n");

    quic_endpoint_on_timeout(ctx->quic_endpoint);
    process_connections(h);
}

static int tquic_socket_create(URLContext *h, struct addrinfo **peer, struct addrinfo **local) {
    TQUICContext *s = h->priv_data;
    int socket_fd;

    const struct addrinfo hints = { .ai_family = AF_UNSPEC, 
                                    .ai_socktype = SOCK_DGRAM,
                                    .ai_protocol = IPPROTO_UDP};
    
    //resolve remote address and port
    if (getaddrinfo(s->remote_addr, s->remote_port, &hints, peer) != 0) {
        av_log(h, AV_LOG_ERROR, "tquic: fail to resolve tquic remote address or post\n");
        return AVERROR(EINVAL);
    }

    if (getaddrinfo(s->local_addr, s->local_port, &hints, local) != 0) {
        av_log(h, AV_LOG_ERROR, "tquic: fail to resolve tquic local address or post\n");
        return AVERROR(EINVAL);
    }

    socket_fd = socket((*peer)->ai_family, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        ff_log_net_error(h, AV_LOG_ERROR, "socket");
    }

    if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) != 0) {
        ff_log_net_error(h, AV_LOG_ERROR, "socket set nonblock");
    }

    if (bind(socket_fd, (*local)->ai_addr, (*local)->ai_addrlen) != 0) {
        ff_log_net_error(h, AV_LOG_ERROR, "socket local bind");
    }

    // s->local_addr_storage_len = sizeof(s->local_addr_storage);
    // if(getsockname(socket_fd, (struct sockaddr *)&s->local_addr_storage, &s->local_addr_storage_len) != 0) {
    //     ff_log_net_error(h, AV_LOG_ERROR, "socket get local addr");
    // }

    s->socket_fd = socket_fd;

    return 0;
}

static void debug_log(const uint8_t *data, size_t data_len, void *argp) {
    av_log(argp, AV_LOG_TRACE, "%s", data);
}

// New: enhanced address retrieval function to get wifi and cellular addresses separately
static int get_network_addresses(TQUICContext *s)
{
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[NI_MAXHOST];
    int found_wifi = 0;
    int found_cellular = 0;

    // Initialize addresses with default values
    strncpy(s->wifi_addr, "0.0.0.0", INET_ADDRSTRLEN);
    strncpy(s->cellular_addr, "0.0.0.0", INET_ADDRSTRLEN);

    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }

    // Iterate through all network interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        // Only process IPv4 addresses
        if (family == AF_INET) {
            int ret_val = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                               host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (ret_val != 0) {
                continue;
            }

            // Ignore loopback, docker and veth interfaces
            if (strcmp(ifa->ifa_name, "lo") != 0 && 
                strncmp(ifa->ifa_name, "docker", 6) != 0 &&
                strncmp(ifa->ifa_name, "veth", 4) != 0) {
                
                // Ignore loopback addresses and link-local addresses
                if (strcmp(host, "127.0.0.1") != 0 && 
                    strncmp(host, "169.254", 7) != 0) {
                    
                    // Identify wifi interfaces (usually start with en, like en0, en1, etc.)
                    if (strncmp(ifa->ifa_name, "en", 2) == 0) {
                        if (!found_wifi) {
                            strncpy(s->wifi_addr, host, INET_ADDRSTRLEN - 1);
                            s->wifi_addr[INET_ADDRSTRLEN - 1] = '\0';
                            found_wifi = 1;
                        }
                    }
                    // Identify cellular interfaces (on iOS usually pdp_ip0, pdp_ip1, etc.)
                    else if (strncmp(ifa->ifa_name, "pdp_ip", 6) == 0) {
                        if (!found_cellular) {
                            strncpy(s->cellular_addr, host, INET_ADDRSTRLEN - 1);
                            s->cellular_addr[INET_ADDRSTRLEN - 1] = '\0';
                            found_cellular = 1;
                        }
                    }
                }
            }
        }
    }

    freeifaddrs(ifaddr);

    return 0;
}

static int tquic_open(URLContext *h, const char *uri, int flags)
{
    TQUICContext *s = h->priv_data;
    char hostname[1024]; //remote host
    int des_port; //remote port
    uint64_t connection_index;
    const char *p;
    char buf[256];
    int ret;

    const char *const protos[1] = {"http/0.9"}; // Only support http/0.9

    s->use_wifi_flag = 1; // default use wifi
    p = strchr(uri, '?');
    if(p) {
        // Parse use_wifi parameter
        if (av_find_info_tag(buf, sizeof(buf), "use_wifi", p)) {
            int use_wifi = atoi(buf);
            if (use_wifi == 0 || use_wifi == 1) {
                s->use_wifi_flag = use_wifi;
                av_log(h, AV_LOG_INFO, "URI parameter set use_wifi=%d\n", use_wifi);
            } else {
                av_log(h, AV_LOG_WARNING, "Invalid use_wifi value: %s, using default: %d\n", buf, s->use_wifi_flag);
            }
        }
    }
    
    // Use the new address retrieval function to get wifi and cellular addresses
    if (get_network_addresses(s) == 0) {
        // Check if we actually got valid addresses (not the default "0.0.0.0")
        int has_valid_wifi = (strcmp(s->wifi_addr, "0.0.0.0") != 0);
        int has_valid_cellular = (strcmp(s->cellular_addr, "0.0.0.0") != 0);
        
        // Select wifi or cellular address based on flag and availability
        if (s->use_wifi_flag) {
            if (!has_valid_wifi) {
                av_log(h, AV_LOG_WARNING, "No valid WiFi address found\n");
            } else {
                av_log(h, AV_LOG_INFO, "Using WiFi address: %s\n", s->wifi_addr);
            }
            s->local_addr = av_strdup(s->wifi_addr);
        } else{
            if (!has_valid_cellular) {
                av_log(h, AV_LOG_WARNING, "No valid Cellular address found\n");
            } else {
                av_log(h, AV_LOG_INFO, "Using Cellular address: %s\n", s->cellular_addr);
            }
            s->local_addr = av_strdup(s->cellular_addr);
        } 
    } else {
        // If retrieval fails, use default address
        s->local_addr = av_strdup("0.0.0.0");
        av_log(h, AV_LOG_WARNING, "Failed to get network addresses, using default: 0.0.0.0\n");
    }
    
    s->local_port = av_strdup("0");  // use port 0 to let OS assign a random port
    s->read_ready_flag = false;
    
    pthread_mutex_init(&s->read_write_mutex, NULL); // Initialize mutex

    quic_set_logger(debug_log, h, "TRACE");
    
    av_log(h, AV_LOG_TRACE, "uri: %s\n", uri);
    // Analysis URI (tquic://host:port/path)
    av_url_split(NULL, 0, NULL, 0, hostname, sizeof(hostname), &des_port, s->path, sizeof(s->path), uri);

    // Remove query parameters from path before sending to server
    char *query_start = strchr(s->path, '?');
    if (query_start) {
        *query_start = '\0';  // Truncate at the '?' character
        av_log(h, AV_LOG_DEBUG, "Removed query parameters from path, clean path: %s\n", s->path);
    }

    s->remote_addr = av_strdup(hostname);
    s->remote_port = av_asprintf("%d", des_port);
    
    // Create socket
    if (tquic_socket_create(h, &s->peer, &s->local) < 0) {
        ret = AVERROR(EINVAL);
        goto fail;
    }

    // Init TQUICContext
    s->quic_endpoint = NULL;
    s->quic_conn = NULL;
    s->tls_config = NULL;

    // Init TQUIC config
    s->tquic_config = quic_config_new();
    if (s->tquic_config == NULL) {
        av_log(h, AV_LOG_ERROR, "tquic: cannot init TQUIC\n");
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    quic_config_set_max_idle_timeout(s->tquic_config, 30000);
    quic_config_set_recv_udp_payload_size(s->tquic_config, MAX_TQUIC_DATAGRAM_SIZE);
    quic_config_set_initial_max_streams_bidi(s->tquic_config, 10);

    // Init TQUIC tls config
    s->tls_config = quic_tls_config_new_client_config(protos, 1, true);
    if (s->tls_config == NULL) {
        av_log(h, AV_LOG_ERROR, "tquic: cannot init TQUIC TLS config\n");
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    quic_config_set_tls_config(s->tquic_config, s->tls_config);

    // Init TQUIC endpoint
    s->quic_endpoint = quic_endpoint_new(s->tquic_config, false, &quic_transport_methods, h, &quic_packet_send_methods, h);
    if (!s->quic_endpoint) {
        av_log(h, AV_LOG_ERROR, "tquic: cannot create endpoint\n");
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    // Init event loop
    s->loop = ev_default_loop(0);
    ev_init(&s->timer, timeout_callback);
    s->timer.data = h;

    // Get TQUIC connection and TQUIC stream
    ret = quic_endpoint_connect(s->quic_endpoint, 
                                s->local->ai_addr, 
                                s->local->ai_addrlen, 
                                s->peer->ai_addr, 
                                s->peer->ai_addrlen,
                                NULL,   // server name
                                NULL,   // session
                                0,      //session length
                                NULL,   //token
                                0,      //token length
                                NULL,   //config
                                &connection_index);  //index
    if (ret < 0) {
        av_log(h, AV_LOG_ERROR, "tquic: cannot connect to server.\n");
        ret = AVERROR(EIO);
        goto fail;
    }

    // Process connection
    process_connections(h);

    // Start event loop.
    ret = pthread_create(&s->receive_thread, NULL, event_loop_thread, h);
    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "tquic: cannot create receive thread: %s\n", strerror(ret));
        ret = AVERROR(EIO);
        goto fail;
    }

    while(!s->read_ready_flag){
        usleep(100000);
    }
    av_log(h, AV_LOG_TRACE, "tquic_open finish\n");
    return ret;

fail:
    if (s->local_addr != NULL){
        av_freep(&s->local_addr);
    }
    if (s->local_port != NULL){
        av_freep(&s->local_port);
    }
    
    if (s->peer != NULL){
        freeaddrinfo(s->peer);
    }

    if (s->tls_config != NULL) {
        quic_tls_config_free(s->tls_config);
    }

    if (s->socket_fd > 0){
        close(s->socket_fd);
    }

    if (s->quic_endpoint != NULL) {
        quic_endpoint_free(s->quic_endpoint);
    }

    if (s->loop != NULL) {
        ev_loop_destroy(s->loop);
    }

    if (s->tquic_config != NULL) {
        quic_config_free(s->tquic_config);
    }

    return ret;
}

static int tquic_read(URLContext *h, uint8_t *buf, int size)
{
    TQUICContext *s = h->priv_data;
    int ret;
    
    pthread_mutex_lock(&s->read_write_mutex);
    av_log(h, AV_LOG_TRACE, "start read from tquic, need read size = %d\n", size);
    ret = (int)quic_stream_read(s->quic_conn, s->quic_stream_id, buf, size, &s->fin_flag);
    av_log(h, AV_LOG_TRACE, "finish read data from tquic, have read length: %d\n", ret);
    pthread_mutex_unlock(&s->read_write_mutex);

    if (ret < 0) {
        return  ff_neterrno();
    }
    
    //read fin from quic stream
    return ret;
}

static int tquic_close(URLContext *h)
{
    TQUICContext *s = h->priv_data;
    av_log(h, AV_LOG_TRACE, "entering tquic_close\n");

#if defined(PLATFORM_IOS)
    av_log(h, AV_LOG_INFO, "iOS platform: TQUIC connection closed\n");
#elif defined(PLATFORM_MACOS)
    av_log(h, AV_LOG_INFO, "macOS platform: TQUIC connection closed\n");
#elif defined(PLATFORM_LINUX)
    av_log(h, AV_LOG_INFO, "Linux platform: TQUIC connection closed\n\n");
#else
    av_log(h, AV_LOG_INFO, "Unix-like platform: TQUIC connection closed\n\n");
#endif

    pthread_mutex_destroy(&s->read_write_mutex);

    if (s->local_addr != NULL){
        av_freep(&s->local_addr);
    }
    if (s->local_port != NULL){
        av_freep(&s->local_port);
    }

    if (s->peer != NULL) {
        freeaddrinfo(s->peer);
    }

    if (s->tls_config != NULL) {
        quic_tls_config_free(s->tls_config);
    }

    if (s->socket_fd > 0){
        close(s->socket_fd);
    }

    if (s->quic_endpoint != NULL) {
        quic_endpoint_free(s->quic_endpoint);
    }

    if (s->loop != NULL) {
        ev_loop_destroy(s->loop);
    }

    if (s->tquic_config != NULL) {
        quic_config_free(s->tquic_config);
    }

    return 0;
}

// 定义URLProtocol
const URLProtocol ff_tquic_protocol = {
    .name            = "tquic",
    .url_open        = tquic_open,
    .url_read        = tquic_read,
    .url_close       = tquic_close,
    .priv_data_size  = sizeof(TQUICContext),
    .priv_data_class = &tquic_class,
    .flags           = URL_PROTOCOL_FLAG_NETWORK,
};
