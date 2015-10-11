signature bittorrent-tcp {
    ip-proto == tcp
    src-port >= 1024
    payload /.*BitTorrent protocol/
    event "bittorrent-tcp"
}
