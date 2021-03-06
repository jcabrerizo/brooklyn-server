/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.brooklyn.util.stream;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Locale;

/** PrintStream which simply delegates to the implementation of getDelegate() */
public abstract class DelegatingPrintStream extends PrintStream {
    
    public DelegatingPrintStream() {
        super(new IllegalOutputStream());
    }
    
    protected abstract PrintStream getDelegate();

    @Override
    public int hashCode() {
        return getDelegate().hashCode();
    }

    @Override
    public void write(byte[] b) throws IOException {
        getDelegate().write(b);
    }

    @Override
    public boolean equals(Object obj) {
        return getDelegate().equals(obj);
    }

    @Override
    public String toString() {
        return getDelegate().toString();
    }

    @Override
    public void flush() {
        getDelegate().flush();
    }

    @Override
    public void close() {
        getDelegate().close();
    }

    @Override
    public boolean checkError() {
        return getDelegate().checkError();
    }

    @Override
    public void write(int b) {
        getDelegate().write(b);
    }

    @Override
    public void write(byte[] buf, int off, int len) {
        getDelegate().write(buf, off, len);
    }

    @Override
    public void print(boolean b) {
        getDelegate().print(b);
    }

    @Override
    public void print(char c) {
        getDelegate().print(c);
    }

    @Override
    public void print(int i) {
        getDelegate().print(i);
    }

    @Override
    public void print(long l) {
        getDelegate().print(l);
    }

    @Override
    public void print(float f) {
        getDelegate().print(f);
    }

    @Override
    public void print(double d) {
        getDelegate().print(d);
    }

    @Override
    public void print(char[] s) {
        getDelegate().print(s);
    }

    @Override
    public void print(String s) {
        getDelegate().print(s);
    }

    @Override
    public void print(Object obj) {
        getDelegate().print(obj);
    }

    @Override
    public void println() {
        getDelegate().println();
    }

    @Override
    public void println(boolean x) {
        getDelegate().println(x);
    }

    @Override
    public void println(char x) {
        getDelegate().println(x);
    }

    @Override
    public void println(int x) {
        getDelegate().println(x);
    }

    @Override
    public void println(long x) {
        getDelegate().println(x);
    }

    @Override
    public void println(float x) {
        getDelegate().println(x);
    }

    @Override
    public void println(double x) {
        getDelegate().println(x);
    }

    @Override
    public void println(char[] x) {
        getDelegate().println(x);
    }

    @Override
    public void println(String x) {
        getDelegate().println(x);
    }

    @Override
    public void println(Object x) {
        getDelegate().println(x);
    }

    @Override
    public PrintStream printf(String format, Object... args) {
        return getDelegate().printf(format, args);
    }

    @Override
    public PrintStream printf(Locale l, String format, Object... args) {
        return getDelegate().printf(l, format, args);
    }

    @Override
    public PrintStream format(String format, Object... args) {
        return getDelegate().format(format, args);
    }

    @Override
    public PrintStream format(Locale l, String format, Object... args) {
        return getDelegate().format(l, format, args);
    }

    @Override
    public PrintStream append(CharSequence csq) {
        return getDelegate().append(csq);
    }

    @Override
    public PrintStream append(CharSequence csq, int start, int end) {
        return getDelegate().append(csq, start, end);
    }

    @Override
    public PrintStream append(char c) {
        return getDelegate().append(c);
    }
    
}
