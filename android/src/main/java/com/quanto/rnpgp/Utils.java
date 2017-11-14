package com.quanto.rnpgp;

import com.quanto.rnpgp.Interfaces.StreamHandler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Created by Lucas Teske on 14/11/17.
 */

class Utils {

  private static final int BUFFER_SIZE = 4096;

  private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

  static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  static void processStream(InputStream is, StreamHandler handler) throws IOException {
    int read;
    byte[] buffer = new byte[BUFFER_SIZE];
    while( (read = is.read(buffer)) != -1 ) {
      handler.handleStreamBuffer(buffer, 0, read);
    }
  }

  static void processStringAsStream(String data, StreamHandler handler) throws IOException {
    InputStream is = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8.name()));
    processStream(is, handler);
  }
}
