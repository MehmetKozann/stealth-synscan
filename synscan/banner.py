import logging
import socket

log = logging.getLogger("synscan")


class BannerGrabber:
    def __init__(self, timeout=4.0):
        self.timeout = timeout

    def grab(self, host, port):
        try:
            s = socket.create_connection((host, port), timeout=self.timeout)
        except OSError as e:
            log.debug("banner conn failed %s:%d (%s)", host, port, e)
            return None
        s.settimeout(self.timeout)
        data = b""
        try:
            data = s.recv(1024)
            if not data:
                s.sendall(b"\r\n")
                data = s.recv(1024)
        except socket.timeout:
            log.debug("banner timeout %s:%d", host, port)
        except OSError as e:
            log.debug("banner read error %s:%d (%s)", host, port, e)
        finally:
            try:
                s.close()
            except OSError:
                pass
        if not data:
            return None
        try:
            return data.decode("utf-8", "replace").strip()[:160] or None
        except Exception as e:
            log.debug("banner decode error: %s", e)
            return None
