package com.quanto.rnpgp.Interfaces;

import java.io.IOException;

/**
 * Created by Lucas Teske on 14/11/17.
 */

public interface StreamHandler {
  void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException;
}
