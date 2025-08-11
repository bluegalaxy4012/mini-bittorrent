package blueg;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;

// decode <bencoded_anything>
// info <torrent_file>
// peers <torrent_file>
// handshake <torrent_file> <peer_ip:port>
// download_piece <output_path> <torrent_file> <piece_index>

public class Main {
    public static void main(String[] args) {
        if (args.length == 0) return;

        String cmd = args[0];

        if ("decode".equals(cmd)) {
            if (args.length != 2) return;

            String input = args[1];

            var inputBytes = input.getBytes(StandardCharsets.UTF_8);

            try {
                Decoder.decode(inputBytes, 0);
            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        } else if ("info".equals(cmd)) {
            if (args.length != 2) return;

            String file = args[1];

            if (!file.endsWith(".torrent")) {
                System.err.println("Expected .torrent file");
                return;
            }

            Torrent torrent = new Torrent();
            torrent.load(file);
            torrent.printAllInfo();
//            try {
//                torrent.getPeers();
//            } catch (Exception e) {
//                throw new RuntimeException(e);
//            }
        } else if ("peers".equals(cmd)) {
            if (args.length != 2) return;

            String file = args[1];

            if (!file.endsWith(".torrent")) {
                System.err.println("Expected .torrent file");
                return;
            }

            Torrent torrent = new Torrent();
            torrent.load(file);
            try {
                torrent.getPeers();
                for (var peer : torrent.getAllPeers())
                    System.out.println(peer);
            } catch (Exception e) {
                System.err.println("Error getting peers: " + e.getMessage());
            }
        } else if ("handshake".equals(cmd)) {
            if (args.length != 3) return;

            String file = args[1];
            String peer = args[2];

            if (!file.endsWith(".torrent")) {
                System.err.println("Expected .torrent file");
                return;
            }

            Torrent torrent = new Torrent();
            torrent.load(file);

            torrent.makeHandshake(peer);
        } else if ("download_piece".equals(cmd)) {
            if (args.length != 4) return;

            String outputPath = args[1];
            String file = args[2];

            int pieceIndex;
            try {
                pieceIndex = Integer.parseInt(args[3]);

                if (pieceIndex < 0) throw new NumberFormatException("Piece index cannot be negative");
            } catch (NumberFormatException e) {
                System.err.println("Invalid piece index: " + args[3]);
                return;
            }

            if (!file.endsWith(".torrent")) {
                System.err.println("Expected .torrent file");
                return;
            }

            Torrent torrent = new Torrent();
            torrent.load(file);
            try {
                torrent.getPeers();
            } catch (Exception e) {
                System.err.println("Error getting peers: " + e.getMessage());
                return;
            }

            torrent.downloadPiece(outputPath, pieceIndex);

        } else {
            System.err.println("Unknown command: " + cmd);
        }
    }
}

class Decoder {

    public static Object[] decode(byte[] input, int idx) throws Exception {
        int startByte = input[idx];

        if (startByte == 'i') {
            int endIdx = idx + 1;
            while (input[endIdx] != 'e') endIdx++;

            String numberString = new String(input, idx + 1, endIdx - idx - 1, StandardCharsets.UTF_8);
            try {
                long value = Long.parseLong(numberString);
                return new Object[]{value, endIdx + 1, "integer"};
            } catch (NumberFormatException e) {
                System.err.println("Invalid integer format");
            }
        } else if (startByte == 'l') {
            List<Object> list = new ArrayList<>();
            int parseIdx = idx + 1;

            while (input[parseIdx] != 'e') {
                Object[] decoded = decode(input, parseIdx);
                list.add(decoded[0]);
                parseIdx = (int) decoded[1];
            }

            return new Object[]{list, parseIdx + 1, "list"};
        } else if (startByte == 'd') {
            Map<String, Object> map = new TreeMap<>();
            int parseIdx = idx + 1;

            while (input[parseIdx] != 'e') {
                Object[] keyDecoded = decode(input, parseIdx);
                byte[] keyBytes = (byte[]) keyDecoded[0];
                String key = new String(keyBytes, StandardCharsets.UTF_8);
                parseIdx = (int) keyDecoded[1];

                Object[] valueDecoded = decode(input, parseIdx);
                Object value = valueDecoded[0];
                parseIdx = (int) valueDecoded[1];

                map.put(key, value);
            }

            return new Object[]{map, parseIdx + 1, "dictionary"};
        } else if (startByte >= '0' && startByte <= '9') {
            int separatorIdx = idx + 1;

            while (input[separatorIdx] != ':') separatorIdx++;

            String lengthString = new String(input, idx, separatorIdx - idx, StandardCharsets.UTF_8);
            int length;

            try {
                length = Integer.parseInt(lengthString);
            } catch (NumberFormatException e) {
                System.err.println("Invalid string length format");
                return null;
            }

            byte[] stringBytes = Arrays.copyOfRange(input, separatorIdx + 1, separatorIdx + 1 + length);


            return new Object[]{stringBytes, separatorIdx + 1 + length, "string"};
        } else throw new Exception("Invalid format, error at index " + idx);
        return null;
    }


    public static Object convertDecodedObject(Object obj) {
        if (obj instanceof byte[]) {
            return new String((byte[]) obj, StandardCharsets.UTF_8);
        } else if (obj instanceof List<?> list) {
            List<Object> converted = new ArrayList<>();
            for (Object item : list) {
                converted.add(convertDecodedObject(item));
            }
            return converted;
        } else if (obj instanceof Map<?, ?> map) {
            Map<Object, Object> converted = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                Object key = entry.getKey();
                Object val = entry.getValue();
                converted.put(convertDecodedObject(key), convertDecodedObject(val));
            }
            return converted;
        } else {
            return obj;
        }
    }


}

class Torrent {
    private final byte[] peerId;
    private String announce;
    private Map<String, Object> info;
    private byte[] infoHash;
    private List<String> pieceHashes;
    private List<String> peers;

    public Torrent() {
        //random peer id

        Random random = new Random();
        this.peerId = new byte[20];

        peerId[0] = '-';
        for (int i = 1; i < this.peerId.length; i++) {
            this.peerId[i] = (byte) ('a' + random.nextInt(26));
        }
    }


    public String getAnnounce() {
        return announce;
    }

    public Map<String, Object> getInfo() {
        return info;
    }

    public byte[] getInfoHash() {
        return infoHash;
    }

    public List<String> getAllPeers() {
        return peers;
    }

    public void downloadPiece(String outputPath, int pieceIndex) {
        String peer = this.peers.get(0);
        String[] parts = peer.split(":");
        String ip = parts[0];
        int port = Integer.parseInt(parts[1]);

        byte[] message = new byte[68];
        message[0] = 19;
        System.arraycopy("BitTorrent protocol".getBytes(StandardCharsets.UTF_8), 0, message, 1, 19);
        Arrays.fill(message, 20, 28, (byte) 0);
        System.arraycopy(this.infoHash, 0, message, 28, this.infoHash.length);
        System.arraycopy(this.peerId, 0, message, 48, this.peerId.length);

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port));
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            out.write(message);
            out.flush();

            byte[] handshakeResponse = new byte[68];
            int hr = 0;
            while (hr < 68) {
                int r = in.read(handshakeResponse, hr, 68 - hr);
                if (r == -1) throw new RuntimeException();
                hr += r;
            }

            byte[] interestedMessage = new byte[]{0, 0, 0, 1, 2};
            out.write(interestedMessage);
            out.flush();

            boolean isChoked = true;
            while (isChoked) {
                byte[] lengthBytes = new byte[4];

                int rb = 0;
                while (rb < 4) {
                    int r = in.read(lengthBytes, rb, 4 - rb);
                    if (r == -1) throw new RuntimeException();
                    rb += r;
                }


                int messageLength = ByteBuffer.wrap(lengthBytes).getInt();
                if (messageLength == 0) continue;

                byte[] messageBody = new byte[messageLength];


                int rbm = 0;
                while (rbm < messageLength) {
                    int r = in.read(messageBody, rbm, messageLength - rbm);

                    if (r == -1) throw new RuntimeException();
                    rbm += r;
                }
                int messageId = messageBody[0] & 0xFF;


                if (messageId == 1) {
                    System.out.println("Received unchoke message");
                    isChoked = false;
                } else if (messageId == 5) {
                    System.out.println("Received bitfield message, ignoring payload");
                } else {
                    System.out.println("Received unexpected message with ID: " + messageId);
                }
            }

            long pieceLength = ((Long) this.info.get("piece length"));
            int pieceSize = (int) pieceLength;

            int blockSize = 16 * 1024;

            int numBlocks = (int) Math.ceil((double) pieceSize / blockSize);
            byte[] pieceData = new byte[pieceSize];

            for (int blockIndex = 0; blockIndex < numBlocks; blockIndex++) {
                int begin = blockIndex * blockSize;
                int length = Math.min(blockSize, pieceSize - begin);

                byte[] requestPayload = new byte[12];
                System.arraycopy(ByteBuffer.allocate(4).putInt(pieceIndex).array(), 0, requestPayload, 0, 4);
                System.arraycopy(ByteBuffer.allocate(4).putInt(begin).array(), 0, requestPayload, 4, 4);
                System.arraycopy(ByteBuffer.allocate(4).putInt(length).array(), 0, requestPayload, 8, 4);

                byte[] requestMessage = new byte[17];
                System.arraycopy(ByteBuffer.allocate(4).putInt(13).array(), 0, requestMessage, 0, 4);
                requestMessage[4] = 6;
                System.arraycopy(requestPayload, 0, requestMessage, 5, 12);

                out.write(requestMessage);
                out.flush();

                while (true) {
                    byte[] lengthBytes = new byte[4];
                    int rb = 0;

                    while (rb < 4) {
                        int r = in.read(lengthBytes, rb, 4 - rb);
                        if (r == -1) throw new RuntimeException();
                        rb += r;
                    }

                    int messageLength = ByteBuffer.wrap(lengthBytes).getInt();
                    if (messageLength == 0) continue;

                    byte[] messageBody = new byte[messageLength];

                    int rbm = 0;
                    while (rbm < messageLength) {
                        int r = in.read(messageBody, rbm, messageLength - rbm);
                        if (r == -1) throw new RuntimeException();
                        rbm += r;
                    }

                    int messageId = messageBody[0] & 0xFF;

                    if (messageId == 7) {
                        int receivedIndex = ByteBuffer.wrap(messageBody, 1, 4).getInt();
                        int receivedBegin = ByteBuffer.wrap(messageBody, 5, 4).getInt();

                        if (receivedIndex == pieceIndex && receivedBegin == begin) {
                            byte[] blockData = Arrays.copyOfRange(messageBody, 9, messageBody.length);
                            System.arraycopy(blockData, 0, pieceData, receivedBegin, blockData.length);

                            break;
                        }
                    } else if (messageId == 0) {
                        System.out.println("Received choke message.");
                    } else {
                        System.out.println("Received unexpected message in block loop with ID: " + messageId);
                    }
                }
            }

            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

            byte[] calculatedHash = sha1.digest(pieceData);
            byte[] expectedHashBytes = new byte[20];
            for (int i = 0; i < 20; i++)
                expectedHashBytes[i] = (byte) Integer.parseInt(this.pieceHashes.get(pieceIndex).substring(i * 2, i * 2 + 2), 16);


            if (Arrays.equals(calculatedHash, expectedHashBytes)) {
                try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                    fos.write(pieceData);
                }
            }

            System.out.println("Piece " + pieceIndex + " downloaded successfully to " + outputPath);

        } catch (Exception e) {
            System.err.println("Error connecting to peer: " + e.getMessage());
        }
    }


    private byte[] calculateInfoHash(byte[] infoBytes) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return sha1.digest(infoBytes);
        } catch (Exception e) {
            System.err.println("Error calculating info hash: " + e.getMessage());
            return new byte[0];
        }
    }

    public void printAllInfo() {
        System.out.println("Announce URL: " + this.announce);
        System.out.println("Info dictionary: " + this.info);

        if (this.infoHash == null || this.infoHash.length == 0) {
            return;
        }

        StringBuilder hexString = new StringBuilder();
        for (byte b : this.infoHash) {
            hexString.append(String.format("%02x", b));
        }

        System.out.println("Info hash (hex): " + hexString);

        System.out.println("Piece hashes: ");
        for (String pieceHash : this.pieceHashes) {
            System.out.println("  " + pieceHash);
        }

    }


    public void getPeers() throws Exception {
        peers = new ArrayList<>();

        HttpClient client = HttpClient.newHttpClient();

        StringBuilder infoHashParam = new StringBuilder();
        for (byte b : this.infoHash) {
            infoHashParam.append('%');
            infoHashParam.append(String.format("%02X", b));
        }
        String info_hash = infoHashParam.toString();

        String peer_id = new String(this.peerId, StandardCharsets.UTF_8);
        String port = "6881";
        String uplodaded = "0";
        String downloaded = "0";
        String left = info.get("length").toString();
        String compact = "1";

        String url = String.format("%s?info_hash=%s&peer_id=%s&port=%s&uploaded=%s&downloaded=%s&left=%s&compact=%s", this.announce, info_hash, peer_id, port, uplodaded, downloaded, left, compact);

        System.out.println("Requesting peers from: " + url);

        var request = HttpRequest.newBuilder().uri(new URI(url)).GET().build();

        var response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());

        if (response.statusCode() != 200) {
            return;
        }

        byte[] responseBody = response.body();

        var decodedResponse = Decoder.decode(responseBody, 0);
        var decodedMap = (Map<String, Object>) decodedResponse[0];

        byte[] peersBytes = (byte[]) decodedMap.get("peers");
        for (int i = 0; i < peersBytes.length; i += 6) {
            StringBuilder peer = new StringBuilder();

            var peer_ip = String.format("%d.%d.%d.%d", peersBytes[i] & 0xFF, peersBytes[i + 1] & 0xFF, peersBytes[i + 2] & 0xFF, peersBytes[i + 3] & 0xFF);
            var peer_port = (peersBytes[i + 5] & 0xFF) + ((peersBytes[i + 4] & 0xFF) << 8);

            peer.append(peer_ip).append(":").append(peer_port);
            peers.add(peer.toString());
        }

    }

    public void makeHandshake(String peer) {
        if (peer == null || peer.isEmpty()) return;

        String[] parts = peer.split(":");
        if (parts.length != 2) {
            System.err.println("Invalid peer address format");
            return;
        }

        String ip = parts[0];
        String port = parts[1];

        byte[] message = new byte[68];

        //0 -> length of protocol string
        message[0] = 19;

        //1-19 -> "BitTorrent protocol"
        System.arraycopy("BitTorrent protocol".getBytes(StandardCharsets.UTF_8), 0, message, 1, 19);

        //20-27 -> reserved bytes (all 0)
        Arrays.fill(message, 20, 28, (byte) 0);

        //28-47 -> info hash
        System.arraycopy(this.infoHash, 0, message, 28, this.infoHash.length);

        //48-67 -> peer id
        System.arraycopy(this.peerId, 0, message, 48, this.peerId.length);

        //now we create tcp connection to the peer

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, Integer.parseInt(port)));

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            out.write(message);
            out.flush();

            byte[] response = new byte[68];
            int bytesRead = in.read(response);

            if (bytesRead < 68) {
                System.err.println("Handshake failed, received less than 68 bytes");
                return;
            }

            byte[] responsePeerId = Arrays.copyOfRange(response, 48, 68);

            StringBuilder peerIdHex = new StringBuilder();
            for (byte b : responsePeerId) {
                peerIdHex.append(String.format("%02x", b));
            }

            System.out.println("Handshake successful with peer: " + peer + ", Peer ID: " + peerIdHex);

        } catch (Exception e) {
            System.err.println("Error connecting to peer: " + e.getMessage());
        }

    }


    public void load(String file) {
        System.out.println("Loading torrent file: " + file);

        File torrentFile = new File(file);
        byte[] torrentContent;

        try {
            torrentContent = Files.readAllBytes(torrentFile.toPath());
        } catch (Exception e) {
            System.err.println("Error reading torrent file: " + e.getMessage());
            return;
        }

        Object[] decodedContent;
        try {
            decodedContent = Decoder.decode(torrentContent, 0);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return;
        }

        if (decodedContent.length < 3 || !"dictionary".equals(decodedContent[2])) {
            System.err.println("Invalid torrent file format");
            return;
        }

        var rawTorrentMap = (Map<String, Object>) decodedContent[0];
        var rawTorrentInfoMap = (Map<String, Object>) rawTorrentMap.get("info");

        var torrentMap = (Map<String, Object>) Decoder.convertDecodedObject(rawTorrentMap);
        var torrentInfoMap = (Map<String, Object>) Decoder.convertDecodedObject(rawTorrentInfoMap);

        this.announce = (String) torrentMap.get("announce");
        this.info = torrentInfoMap;

        int infoStartIdx = 0;
        int infoEndIdx = 0;

        for (int i = 0; i < torrentContent.length - 6; i++) {
            if (torrentContent[i] == '4' && torrentContent[i + 1] == ':' && torrentContent[i + 2] == 'i' && torrentContent[i + 3] == 'n' && torrentContent[i + 4] == 'f' && torrentContent[i + 5] == 'o') {
                infoStartIdx = i + 6;
                try {
                    var rawTorrentInfoObject = Decoder.decode(torrentContent, infoStartIdx);
                    infoEndIdx = (int) rawTorrentInfoObject[1];
                } catch (Exception e) {
                    System.err.println("Error decoding info section: " + e.getMessage());
                    return;
                }
                break;
            }
        }
        byte[] infoBytes = Arrays.copyOfRange(torrentContent, infoStartIdx, infoEndIdx);
        this.infoHash = calculateInfoHash(infoBytes);

        byte[] pieceHashesBytes = (byte[]) rawTorrentInfoMap.get("pieces");
        this.pieceHashes = new ArrayList<>();

        for (int i = 0; i < pieceHashesBytes.length; i += 20) {
            byte[] pieceHash = Arrays.copyOfRange(pieceHashesBytes, i, i + 20);

            StringBuilder hexString = new StringBuilder();
            for (byte b : pieceHash) {
                hexString.append(String.format("%02x", b));
            }

            this.pieceHashes.add(hexString.toString());
        }
    }
}
