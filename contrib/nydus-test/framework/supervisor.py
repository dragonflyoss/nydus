import socket
import array
import os
import struct
from multiprocessing import Process
import threading
import time


class RafsSupervisor:
    def __init__(self, watcher_socket_name, conn_id):
        self.watcher_socket_name = watcher_socket_name
        self.conn_id = conn_id

    @classmethod
    def recv_fds(cls, sock, msglen, maxfds):
        """Function from https://docs.python.org/3/library/socket.html#socket.socket.recvmsg"""
        fds = array.array("i")  # Array of ints
        msg, ancdata, flags, addr = sock.recvmsg(
            msglen, socket.CMSG_LEN(maxfds * fds.itemsize)
        )

        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                # Append data, ignoring any truncated integers at the end.
                fds.frombytes(
                    cmsg_data[: len(cmsg_data) - (len(cmsg_data) % fds.itemsize)]
                )

        return msg, list(fds)

    @classmethod
    def send_fds(cls, sock, msg, fds):
        """Function from https://docs.python.org/3/library/socket.html#socket.socket.sendmsg"""
        return sock.sendmsg(
            [msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))]
        )

    def wait_recv_fd(self, event):
        try:
            os.unlink(self.watcher_socket_name)
        except FileNotFoundError:
            pass

        sock = socket.socket(family=socket.AF_UNIX)
        sock.bind(self.watcher_socket_name)
        event.set()
        sock.listen()

        client, _ = sock.accept()
        msg, fds = self.recv_fds(client, 100000, 1)
        self.fds = fds
        self.opaque = msg
        client.close()

    def wait_send_fd(self):
        try:
            os.unlink(self.watcher_socket_name)
        except FileNotFoundError:
            pass

        sock = socket.socket(family=socket.AF_UNIX)
        sock.bind(self.watcher_socket_name)
        sock.listen()

        client, _ = sock.accept()

        msg = self.opaque

        RafsSupervisor.send_fds(client, msg, self.fds)
        client.close()

    def send_fd(self):
        t = threading.Thread(target=self.wait_send_fd)
        t.start()

    def recv_fd(self):
        event = threading.Event()
        t = threading.Thread(target=self.wait_recv_fd, args=(event,))
        t.start()

        return event
