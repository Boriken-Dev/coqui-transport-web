import 'dart:typed_data';

/// What a data channel attempt tells the channel it belongs to.
abstract interface class DataChannelEvents {
  void signal(Uint8List signal);
  void opened();
  void ended();
  void arrived(Uint8List datagram);
  void discarded();
}

/// One data channel attempt, and the path once it opens.
abstract interface class DataChannelPath {
  bool get isOpen;
  int get maxSize;
  void send(Uint8List datagram);
  void deliver(Uint8List signal);
  void close();
}
