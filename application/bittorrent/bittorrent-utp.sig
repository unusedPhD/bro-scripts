signature bittorrent-utp {
    ip-proto == udp
    src-port >= 1024
    payload /.*BitTorrent protocol/
    event "bittorrent-utp"
}
