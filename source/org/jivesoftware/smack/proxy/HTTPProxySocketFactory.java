package org.jivesoftware.smack.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jivesoftware.smack.proxy.SocketConnectorFactory.SocketConnector;
import org.jivesoftware.smack.util.Base64;

/**
 * Http Proxy Socket Factory which returns socket connected to Http Proxy
 * 
 * @author Atul Aggarwal
 */
class HTTPProxySocketFactory 
    extends SocketConnectorFactory
{
    private ProxyInfo proxy;

    public HTTPProxySocketFactory(ProxyInfo proxy) { this.proxy = proxy; }
    public SocketConnector createConnector(Socket socket) { return new HTTPProxySocketConnector(socket, proxy); }
}

class HTTPProxySocketConnector extends SocketConnector
{
    private Socket socket;
    private final ProxyInfo proxy;

    public HTTPProxySocketConnector(Socket socket, ProxyInfo proxy) {
        this.socket = socket;
        this.proxy = proxy;
    }
    public void connectSocket(String host, int port) throws IOException {
        // XXX: this should be resolved async
        String proxyhost = proxy.getProxyAddress();
        int proxyPort = proxy.getProxyPort();
        socket.connect(new InetSocketAddress(proxyhost, proxyPort));

        String hostport = "CONNECT " + host + ":" + port;
        String proxyLine;
        String username = proxy.getProxyUsername();
        if (username == null)
        {
            proxyLine = "";
        }
        else
        {
            String password = proxy.getProxyPassword();
            proxyLine = "\r\nProxy-Authorization: Basic "
              + new String (Base64.encodeBytes((username + ":" 
              + password).getBytes("UTF-8")));
        }
        socket.getOutputStream().write((hostport + " HTTP/1.1\r\nHost: "
            + hostport + proxyLine + "\r\n\r\n").getBytes("UTF-8"));
        
        InputStream in = socket.getInputStream();
        StringBuilder got = new StringBuilder(100);
        int nlchars = 0;
        
        while (true)
        {
            char c = (char) in.read();
            got.append(c);
            if (got.length() > 1024)
            {
                throw new ProxyException(ProxyInfo.ProxyType.HTTP, "Recieved " +
                    "header of >1024 characters from "
                    + socket.getRemoteSocketAddress().toString() + ", cancelling connection");
            }
            if (c == -1)
            {
                throw new ProxyException(ProxyInfo.ProxyType.HTTP);
            }
            if ((nlchars == 0 || nlchars == 2) && c == '\r')
            {
                nlchars++;
            }
            else if ((nlchars == 1 || nlchars == 3) && c == '\n')
            {
                nlchars++;
            }
            else
            {
                nlchars = 0;
            }
            if (nlchars == 4)
            {
                break;
            }
        }

        if (nlchars != 4)
        {
            throw new ProxyException(ProxyInfo.ProxyType.HTTP, "Never " +
                "received blank line from " 
                + socket.getRemoteSocketAddress().toString() + ", cancelling connection");
        }

        String gotstr = got.toString();
        
        BufferedReader br = new BufferedReader(new StringReader(gotstr));
        String response = br.readLine();
        
        if (response == null)
        {
            throw new ProxyException(ProxyInfo.ProxyType.HTTP, "Empty proxy " +
                "response from " + socket.getRemoteSocketAddress().toString() + ", cancelling");
        }
        
        Matcher m = RESPONSE_PATTERN.matcher(response);
        if (!m.matches())
        {
            throw new ProxyException(ProxyInfo.ProxyType.HTTP , "Unexpected " +
                "proxy response from " + socket.getRemoteSocketAddress().toString() + ": " + response);
        }
        
        int code = Integer.parseInt(m.group(1));
        
        if (code != HttpURLConnection.HTTP_OK)
        {
            throw new ProxyException(ProxyInfo.ProxyType.HTTP);
        }
    }

    // XXX
    public void cancel() {
    }

    private static final Pattern RESPONSE_PATTERN
        = Pattern.compile("HTTP/\\S+\\s(\\d+)\\s(.*)\\s*");

}
