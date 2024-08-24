/*
 __  __                  _               _               _ 
|  \/  | ___  __ _  __ _| |__   __ _ ___| |_ ___ _ __ __| |
| |\/| |/ _ \/ _` |/ _` | '_ \ / _` / __| __/ _ \ '__/ _` |
| |  | |  __/ (_| | (_| | |_) | (_| \__ \ ||  __/ | | (_| |
|_|  |_|\___|\__, |\__,_|_.__/ \__,_|___/\__\___|_|  \__,_|
             |___/                                         
© Perpetrated by tonikelope since 2016
 */
package com.tonikelope.megabasterd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

import static com.tonikelope.megabasterd.CryptTools.AES_ZERO_IV;
import static com.tonikelope.megabasterd.CryptTools.MEGAPrepareMasterKey;
import static com.tonikelope.megabasterd.CryptTools.MEGAUserHash;
import static com.tonikelope.megabasterd.CryptTools.aes_cbc_decrypt_nopadding;
import static com.tonikelope.megabasterd.CryptTools.aes_cbc_encrypt_nopadding;
import static com.tonikelope.megabasterd.CryptTools.aes_cbc_encrypt_pkcs7;
import static com.tonikelope.megabasterd.CryptTools.aes_ecb_decrypt_nopadding;
import static com.tonikelope.megabasterd.CryptTools.aes_ecb_encrypt_nopadding;
import static com.tonikelope.megabasterd.CryptTools.initMEGALinkKey;
import static com.tonikelope.megabasterd.CryptTools.rsaDecrypt;
import static com.tonikelope.megabasterd.MiscTools.Bin2UrlBASE64;
import static com.tonikelope.megabasterd.MiscTools.UrlBASE642Bin;
import static com.tonikelope.megabasterd.MiscTools.bin2i32a;
import static com.tonikelope.megabasterd.MiscTools.cleanFilename;
import static com.tonikelope.megabasterd.MiscTools.findFirstRegex;
import static com.tonikelope.megabasterd.MiscTools.genID;
import static com.tonikelope.megabasterd.MiscTools.genRandomByteArray;
import static com.tonikelope.megabasterd.MiscTools.getWaitTimeExpBackOff;
import static com.tonikelope.megabasterd.MiscTools.i32a2bin;
import static com.tonikelope.megabasterd.MiscTools.mpi2big;

/**
 * @author tonikelope
 */
public class MegaAPI implements Serializable {

    public static final String API_URL = "https://g.api.mega.co.nz";
    public static String API_KEY = null;
    public static final int REQ_ID_LENGTH = 10;
    public static final Integer[] MEGA_ERROR_NO_EXCEPTION_CODES = {-1, -3};
    public static final int PBKDF2_ITERATIONS = 100000;
    public static final int PBKDF2_OUTPUT_BIT_LENGTH = 256;
    private static final Logger LOG = Logger.getLogger(MegaAPI.class.getName());

    public static int checkMEGAError(final String data) {
        final String error = findFirstRegex("^\\[?(\\-[0-9]+)\\]?$", data, 1);

        return error != null ? Integer.parseInt(error) : 0;
    }

    private long _seqno;

    private String _sid;

    private int[] _master_key;

    private BigInteger[] _rsa_priv_key;

    private int[] _password_aes;

    private String _user_hash;

    private String _root_id;

    private String _inbox_id;

    private String _email;

    private String _full_email;

    private String _trashbin_id;

    private String _req_id;

    private int _account_version;

    private String _salt;

    public MegaAPI() {
        this._req_id = null;
        this._trashbin_id = null;
        this._full_email = null;
        this._email = null;
        this._inbox_id = null;
        this._root_id = null;
        this._user_hash = null;
        this._password_aes = null;
        this._rsa_priv_key = null;
        this._master_key = null;
        this._salt = null;
        this._sid = null;
        this._account_version = -1;
        this._req_id = genID(REQ_ID_LENGTH);

        final Random randomno = new Random();
        this._seqno = randomno.nextLong() & 0xffffffffL;
    }

    public int getAccount_version() {
        return this._account_version;
    }

    public String getFull_email() {
        return this._full_email;
    }

    public String getEmail() {
        return this._email;
    }

    public int[] getPassword_aes() {
        return this._password_aes;
    }

    public String getUser_hash() {
        return this._user_hash;
    }

    public String getSid() {
        return this._sid;
    }

    public int[] getMaster_key() {
        return this._master_key;
    }

    public BigInteger[] getRsa_priv_key() {
        return this._rsa_priv_key;
    }

    public String getRoot_id() {
        return this._root_id;
    }

    public String getInbox_id() {
        return this._inbox_id;
    }

    public String getTrashbin_id() {
        return this._trashbin_id;
    }

    private void _realLogin(final String pincode) throws Exception {

        final String request;

        if (pincode != null) {
            request = "[{\"a\":\"us\", \"mfa\":\"" + pincode + "\", \"user\":\"" + this._email + "\",\"uh\":\"" + this._user_hash + "\"}]";
        } else {
            request = "[{\"a\":\"us\",\"user\":\"" + this._email + "\",\"uh\":\"" + this._user_hash + "\"}]";
        }

        final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno));

        final String res = this.RAW_REQUEST(request, url_api);

        final ObjectMapper objectMapper = new ObjectMapper();

        final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

        final String k = (String) res_map[0].get("k");

        final String privk = (String) res_map[0].get("privk");

        this._master_key = bin2i32a(this.decryptKey(UrlBASE642Bin(k), i32a2bin(this._password_aes)));

        final String csid = (String) res_map[0].get("csid");

        if (csid != null) {

            final int[] enc_rsa_priv_key = bin2i32a(UrlBASE642Bin(privk));

            final byte[] privk_byte = this.decryptKey(i32a2bin(enc_rsa_priv_key), i32a2bin(this._master_key));

            this._rsa_priv_key = this._extractRSAPrivKey(privk_byte);

            final byte[] raw_sid = rsaDecrypt(mpi2big(UrlBASE642Bin(csid)), this._rsa_priv_key[0], this._rsa_priv_key[1], this._rsa_priv_key[2]);

            this._sid = Bin2UrlBASE64(Arrays.copyOfRange(raw_sid, 0, 43));
        }

        this.fetchNodes();
    }

    private void _readAccountVersionAndSalt() throws Exception {

        final String request = "[{\"a\":\"us0\",\"user\":\"" + this._email + "\"}]";

        final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno));

        final String res = this.RAW_REQUEST(request, url_api);

        final ObjectMapper objectMapper = new ObjectMapper();

        final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

        this._account_version = (Integer) res_map[0].get("v");

        this._salt = (String) res_map[0].get("s");

    }

    public boolean check2FA(final String email) throws Exception {

        final String request = "[{\"a\":\"mfag\",\"e\":\"" + email + "\"}]";

        final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno));

        final String res = this.RAW_REQUEST(request, url_api);

        final ObjectMapper objectMapper = new ObjectMapper();

        final Integer[] res_map = objectMapper.readValue(res, Integer[].class);

        return (res_map[0] == 1);

    }

    public void login(final String email, final String password, final String pincode) throws Exception {

        this._full_email = email;

        final String[] email_split = email.split(" *# *");

        this._email = email_split[0];

        if (this._account_version == -1) {
            this._readAccountVersionAndSalt();
        }

        if (this._account_version == 1) {

            this._password_aes = MEGAPrepareMasterKey(bin2i32a(password.getBytes("UTF-8")));

            this._user_hash = MEGAUserHash(this._email.toLowerCase().getBytes("UTF-8"), this._password_aes);

        } else {

            final byte[] pbkdf2_key = CryptTools.PBKDF2HMACSHA512(password, MiscTools.UrlBASE642Bin(this._salt), PBKDF2_ITERATIONS, PBKDF2_OUTPUT_BIT_LENGTH);

            this._password_aes = bin2i32a(Arrays.copyOfRange(pbkdf2_key, 0, 16));

            this._user_hash = MiscTools.Bin2UrlBASE64(Arrays.copyOfRange(pbkdf2_key, 16, 32));
        }

        this._realLogin(pincode);
    }

    public void fastLogin(final String email, final int[] password_aes, final String user_hash, final String pincode) throws Exception {

        this._full_email = email;

        final String[] email_split = email.split(" *# *");

        this._email = email_split[0];

        if (this._account_version == -1) {
            this._readAccountVersionAndSalt();
        }

        this._password_aes = password_aes;

        this._user_hash = user_hash;

        this._realLogin(pincode);
    }

    public Long[] getQuota() {

        Long[] quota = null;

        try {
            final String request = "[{\"a\": \"uq\", \"xfer\": 1, \"strg\": 1}]";

            final URL url_api;

            url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

            quota = new Long[2];

            if (res_map[0].get("cstrg") instanceof Integer) {

                quota[0] = ((Number) res_map[0].get("cstrg")).longValue();

            } else if (res_map[0].get("cstrg") instanceof Long) {

                quota[0] = (Long) res_map[0].get("cstrg");
            }

            if (res_map[0].get("mstrg") instanceof Integer) {

                quota[1] = ((Number) res_map[0].get("mstrg")).longValue();

            } else if (res_map[0].get("mstrg") instanceof Long) {

                quota[1] = (Long) res_map[0].get("mstrg");
            }

        } catch (final Exception ex) {

            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return quota;
    }

    public void fetchNodes() throws IOException {

        final String request = "[{\"a\":\"f\", \"c\":1}]";

        final URL url_api;

        try {

            url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

            for (final Object o : (Iterable<? extends Object>) res_map[0].get("f")) {

                final HashMap element = (HashMap<String, Object>) o;

                final int file_type = (int) element.get("t");

                switch (file_type) {

                    case 2:
                        this._root_id = (String) element.get("h");
                        break;
                    case 3:
                        this._inbox_id = (String) element.get("h");
                        break;
                    case 4:
                        this._trashbin_id = (String) element.get("h");
                        break;
                    default:
                        break;
                }
            }

        } catch (final IOException | MegaAPIException ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

    }

    private String RAW_REQUEST(final String request, final URL url_api) throws MegaAPIException {

        String response = null, current_smart_proxy = null;

        int mega_error = 0, http_error = 0, conta_error = 0, http_status;

        boolean empty_response = false, smart_proxy_socks = false;

        HttpsURLConnection con = null;

        final ArrayList<String> excluded_proxy_list = new ArrayList<>();

        do {

            final SmartMegaProxyManager proxy_manager = MainPanel.getProxy_manager();

            try {

                if ((current_smart_proxy != null || http_error == 509) && MainPanel.isUse_smart_proxy() && proxy_manager != null && !MainPanel.isUse_proxy()) {

                    if (current_smart_proxy != null && (http_error != 0 || empty_response)) {

                        proxy_manager.blockProxy(current_smart_proxy, "HTTP " + String.valueOf(http_error));

                        final String[] smart_proxy = proxy_manager.getProxy(excluded_proxy_list);

                        current_smart_proxy = smart_proxy[0];

                        smart_proxy_socks = smart_proxy[1].equals("socks");

                    } else if (current_smart_proxy == null) {

                        final String[] smart_proxy = proxy_manager.getProxy(excluded_proxy_list);

                        current_smart_proxy = smart_proxy[0];

                        smart_proxy_socks = smart_proxy[1].equals("socks");
                    }

                    if (current_smart_proxy != null) {

                        final String[] proxy_info = current_smart_proxy.split(":");

                        final Proxy proxy = new Proxy(smart_proxy_socks ? Proxy.Type.SOCKS : Proxy.Type.HTTP, new InetSocketAddress(proxy_info[0], Integer.parseInt(proxy_info[1])));

                        con = (HttpsURLConnection) url_api.openConnection(proxy);

                    } else {

                        con = (HttpsURLConnection) url_api.openConnection();
                    }

                } else {

                    if (MainPanel.isUse_proxy()) {

                        con = (HttpsURLConnection) url_api.openConnection(new Proxy(smart_proxy_socks ? Proxy.Type.SOCKS : Proxy.Type.HTTP, new InetSocketAddress(MainPanel.getProxy_host(), MainPanel.getProxy_port())));

                        if (MainPanel.getProxy_user() != null && !"".equals(MainPanel.getProxy_user())) {

                            con.setRequestProperty("Proxy-Authorization", "Basic " + MiscTools.Bin2BASE64((MainPanel.getProxy_user() + ":" + MainPanel.getProxy_pass()).getBytes("UTF-8")));
                        }
                    } else {

                        con = (HttpsURLConnection) url_api.openConnection();
                    }

                }

                http_error = 0;

                mega_error = 0;

                empty_response = false;

                con.setRequestProperty("Content-type", "text/plain;charset=UTF-8");

                con.setRequestProperty("Accept-Encoding", "gzip");

                con.setRequestProperty("User-Agent", MainPanel.DEFAULT_USER_AGENT);

                con.setUseCaches(false);

                con.setRequestMethod("POST");

                con.setDoOutput(true);

                con.getOutputStream().write(request.getBytes("UTF-8"));

                con.getOutputStream().close();

                http_status = con.getResponseCode();

                if (http_status != 200) {

                    LOG.log(Level.WARNING, "{0} {1} {2}", new Object[]{Thread.currentThread().getName(), request, url_api.toString()});

                    LOG.log(Level.WARNING, "{0} Failed : HTTP error code : {1}", new Object[]{Thread.currentThread().getName(), http_status});

                    http_error = http_status;

                } else {

                    try (final InputStream is = "gzip".equals(con.getContentEncoding()) ? new GZIPInputStream(con.getInputStream()) : con.getInputStream(); final ByteArrayOutputStream byte_res = new ByteArrayOutputStream()) {

                        final byte[] buffer = new byte[MainPanel.DEFAULT_BYTE_BUFFER_SIZE];

                        int reads;

                        while ((reads = is.read(buffer)) != -1) {

                            byte_res.write(buffer, 0, reads);
                        }

                        response = new String(byte_res.toByteArray(), "UTF-8");

                        if (response.length() > 0) {

                            mega_error = checkMEGAError(response);

                            if (mega_error != 0 && !Arrays.asList(MEGA_ERROR_NO_EXCEPTION_CODES).contains(mega_error)) {

                                throw new MegaAPIException(mega_error);

                            }

                        } else {

                            empty_response = true;
                        }
                    }

                }

            } catch (final SSLException ssl_ex) {

                empty_response = true;

                Logger.getLogger(MegaAPI.class.getName()).log(Level.SEVERE, ssl_ex.getMessage());

            } catch (final IOException ex) {

                Logger.getLogger(MegaAPI.class.getName()).log(Level.SEVERE, ex.getMessage());

            } finally {

                if (con != null) {
                    con.disconnect();
                }

            }

            if ((empty_response || mega_error != 0 || http_error != 0) && http_error != 509) {

                LOG.log(Level.WARNING, "{0} MegaAPI ERROR {1} Waiting for retry...", new Object[]{Thread.currentThread().getName(), String.valueOf(mega_error)});

                try {
                    Thread.sleep(getWaitTimeExpBackOff(conta_error++) * 1000);
                } catch (final InterruptedException ex) {
                    LOG.log(Level.SEVERE, ex.getMessage());
                }

            }

        } while (http_error == 500 || empty_response || mega_error != 0 || (http_error == 509 && MainPanel.isUse_smart_proxy() && !MainPanel.isUse_proxy()));

        this._seqno++;

        return response;

    }

    public String getMegaFileDownloadUrl(final String link) throws MegaAPIException, MalformedURLException, IOException {

        final String file_id = findFirstRegex("#.*?!([^!]+)", link, 1);

        final String request;

        final URL url_api;

        if (findFirstRegex("#N!", link, 0) != null) {
            final String folder_id = findFirstRegex("###n=(.+)$", link, 1);

            request = "[{\"a\":\"g\", \"g\":\"1\", \"n\":\"" + file_id + "\"}]";

            url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : "") + "&n=" + folder_id);

        } else {

            request = "[{\"a\":\"g\", \"g\":\"1\", \"p\":\"" + file_id + "\"}]";
            url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));
        }

        final String data = this.RAW_REQUEST(request, url_api);

        final ObjectMapper objectMapper = new ObjectMapper();

        final HashMap[] res_map = objectMapper.readValue(data, HashMap[].class);

        final String download_url = (String) res_map[0].get("g");

        if (download_url == null || "".equals(download_url)) {
            throw new MegaAPIException(-101);
        }

        return download_url;
    }

    public String[] getMegaFileMetadata(final String link) throws MegaAPIException, MalformedURLException, IOException {

        final String file_id = findFirstRegex("#.*?!([^!]+)", link, 1);

        final String file_key = findFirstRegex("#.*?![^!]+!([^!#]+)", link, 1);

        final String request;

        final URL url_api;

        if (findFirstRegex("#N!", link, 0) != null) {
            final String folder_id = findFirstRegex("###n=(.+)$", link, 1);

            request = "[{\"a\":\"g\", \"g\":\"1\", \"n\":\"" + file_id + "\"}]";

            url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : "") + "&n=" + folder_id);

        } else {

            request = "[{\"a\":\"g\", \"p\":\"" + file_id + "\"}]";

            url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));
        }

        final String data = this.RAW_REQUEST(request, url_api);

        final ObjectMapper objectMapper = new ObjectMapper();

        final HashMap[] res_map = objectMapper.readValue(data, HashMap[].class);

        final String fsize = String.valueOf(res_map[0].get("s"));

        final String at = (String) res_map[0].get("at");

        String[] file_data = null;

        final HashMap att_map = this._decAttr(at, initMEGALinkKey(file_key));

        if (att_map != null) {

            final String fname = cleanFilename((String) att_map.get("n"));

            file_data = new String[]{fname, fsize, file_key};

        } else {

            throw new MegaAPIException(-14);
        }

        return file_data;
    }

    private byte[] _encThumbAttr(final byte[] attr_byte, final byte[] key) {

        try {

            return aes_cbc_encrypt_pkcs7(attr_byte, key, AES_ZERO_IV);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return null;
    }

    private byte[] _encAttr(final String attr, final byte[] key) {

        byte[] ret = null;

        try {

            final byte[] attr_byte = ("MEGA" + attr).getBytes("UTF-8");

            final int l = (int) (16 * Math.ceil((double) attr_byte.length / 16));

            final byte[] new_attr_byte = Arrays.copyOfRange(attr_byte, 0, l);

            ret = aes_cbc_encrypt_nopadding(new_attr_byte, key, AES_ZERO_IV);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return ret;
    }

    private HashMap _decAttr(final String encAttr, final byte[] key) {

        HashMap res_map = null;

        final byte[] decrypted_at;

        try {

            decrypted_at = aes_cbc_decrypt_nopadding(UrlBASE642Bin(encAttr), key, AES_ZERO_IV);

            final String att = new String(decrypted_at, "UTF-8").replaceAll("\0+$", "").replaceAll("^MEGA", "");

            final ObjectMapper objectMapper = new ObjectMapper();

            objectMapper.configure(JsonParser.Feature.ALLOW_SINGLE_QUOTES, true);

            objectMapper.configure(JsonParser.Feature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER, true);

            res_map = objectMapper.readValue(att, HashMap.class);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());

        }

        return res_map;
    }

    public String initUploadFile(final String filename) throws MegaAPIException {

        String ul_url = null;

        try {

            final File f = new File(filename);

            final String request = "[{\"a\":\"u\", \"s\":" + String.valueOf(f.length()) + "}]";

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

            ul_url = (String) res_map[0].get("p");

        } catch (final MegaAPIException mae) {

            throw mae;

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return ul_url;
    }

    public String uploadThumbnails(final Upload upload, final String node_handle, final String filename0, final String filename1) throws MegaAPIException {

        final String[] ul_url = new String[2];

        final String[] hash = new String[2];

        try {

            final File[] files = new File[2];

            files[0] = new File(filename0);

            final byte[][] file_bytes = new byte[2][];

            file_bytes[0] = this._encThumbAttr(Files.readAllBytes(files[0].toPath()), upload.getByte_file_key());

            files[1] = new File(filename1);

            file_bytes[1] = this._encThumbAttr(Files.readAllBytes(files[1].toPath()), upload.getByte_file_key());

            String request = "[{\"a\":\"ufa\", \"s\":" + String.valueOf(file_bytes[0].length) + ", \"ssl\":1}, {\"a\":\"ufa\", \"s\":" + String.valueOf(file_bytes[1].length) + ", \"ssl\":1}]";

            URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            String res = this.RAW_REQUEST(request, url_api);

            ObjectMapper objectMapper = new ObjectMapper();

            final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

            ul_url[0] = (String) res_map[0].get("p");

            ul_url[1] = (String) res_map[1].get("p");

            int h = 0;

            for (final String u : ul_url) {

                final URL url = new URL(u);

                final HttpURLConnection con;

                con = (HttpURLConnection) url.openConnection();

                con.setConnectTimeout(Transference.HTTP_CONNECT_TIMEOUT);

                con.setReadTimeout(Transference.HTTP_READ_TIMEOUT);

                con.setRequestMethod("POST");

                con.setDoOutput(true);

                con.setUseCaches(false);

                con.setRequestProperty("User-Agent", MainPanel.DEFAULT_USER_AGENT);

                final byte[] buffer = new byte[8192];

                int reads;

                try (final OutputStream out = new ThrottledOutputStream(con.getOutputStream(), upload.getMain_panel().getStream_supervisor())) {

                    out.write(file_bytes[h]);
                }

                try (final InputStream is = con.getInputStream(); final ByteArrayOutputStream byte_res = new ByteArrayOutputStream()) {

                    while ((reads = is.read(buffer)) != -1) {
                        byte_res.write(buffer, 0, reads);
                    }

                    hash[h] = MiscTools.Bin2UrlBASE64(byte_res.toByteArray());

                }

                h++;
            }

            request = "[{\"a\":\"pfa\", \"fa\":\"0*" + hash[0] + "/1*" + hash[1] + "\", \"n\":\"" + node_handle + "\"}]";

            url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            res = this.RAW_REQUEST(request, url_api);

            objectMapper = new ObjectMapper();

            final String[] resp = objectMapper.readValue(res, String[].class);

            return (String) resp[0];

        } catch (final MegaAPIException mae) {

            throw mae;

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return "";
    }

    public HashMap<String, Object> finishUploadFile(final String fbasename, final int[] ul_key, final int[] fkey, final int[] meta_mac, final String completion_handle, final String mega_parent, final byte[] master_key, final String root_node, final byte[] share_key) throws MegaAPIException {

        HashMap[] res_map = null;

        try {

            final byte[] enc_att = this._encAttr("{\"n\":\"" + fbasename + "\"}", i32a2bin(Arrays.copyOfRange(ul_key, 0, 4)));

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String request = "[{\"a\":\"p\", \"t\":\"" + mega_parent + "\", \"n\":[{\"h\":\"" + completion_handle + "\", \"t\":0, \"a\":\"" + Bin2UrlBASE64(enc_att) + "\", \"k\":\"" + Bin2UrlBASE64(this.encryptKey(i32a2bin(fkey), master_key)) + "\"}], \"i\":\"" + this._req_id + "\", \"cr\" : [ [\"" + root_node + "\"] , [\"" + completion_handle + "\"] , [0,0, \"" + Bin2UrlBASE64(this.encryptKey(i32a2bin(fkey), share_key)) + "\"]]}]";

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            res_map = objectMapper.readValue(res, HashMap[].class);

        } catch (final MegaAPIException mae) {

            throw mae;

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return res_map != null ? res_map[0] : null;
    }

    public byte[] encryptKey(final byte[] a, final byte[] key) throws Exception {

        return aes_ecb_encrypt_nopadding(a, key);
    }

    public byte[] decryptKey(final byte[] a, final byte[] key) throws Exception {

        return aes_ecb_decrypt_nopadding(a, key);
    }

    private BigInteger[] _extractRSAPrivKey(final byte[] rsa_data) {

        final BigInteger[] rsa_key = new BigInteger[4];

        for (int i = 0, offset = 0; i < 4; i++) {

            final int l = ((256 * ((((int) rsa_data[offset]) & 0xFF)) + (((int) rsa_data[offset + 1]) & 0xFF) + 7) / 8) + 2;

            rsa_key[i] = mpi2big(Arrays.copyOfRange(rsa_data, offset, offset + l));

            offset += l;
        }

        return rsa_key;
    }

    public HashMap<String, Object> createDir(final String name, final String parent_node, final byte[] node_key, final byte[] master_key) {

        HashMap[] res_map = null;

        try {

            final byte[] enc_att = this._encAttr("{\"n\":\"" + name + "\"}", node_key);

            final byte[] enc_node_key = this.encryptKey(node_key, master_key);

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String request = "[{\"a\":\"p\", \"t\":\"" + parent_node + "\", \"n\":[{\"h\":\"xxxxxxxx\",\"t\":1,\"a\":\"" + Bin2UrlBASE64(enc_att) + "\",\"k\":\"" + Bin2UrlBASE64(enc_node_key) + "\"}],\"i\":\"" + this._req_id + "\"}]";

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            res_map = objectMapper.readValue(res, HashMap[].class);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return res_map != null ? res_map[0] : null;

    }

    public HashMap<String, Object> createDirInsideAnotherSharedDir(final String name, final String parent_node, final byte[] node_key, final byte[] master_key, final String root_node, final byte[] share_key) {

        HashMap[] res_map = null;

        try {

            final byte[] enc_att = this._encAttr("{\"n\":\"" + name + "\"}", node_key);

            final byte[] enc_node_key = this.encryptKey(node_key, master_key);

            final byte[] enc_node_key_s = this.encryptKey(node_key, share_key);

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String request = "[{\"a\":\"p\", \"t\":\"" + parent_node + "\", \"n\":[{\"h\":\"xxxxxxxx\",\"t\":1,\"a\":\"" + Bin2UrlBASE64(enc_att) + "\",\"k\":\"" + Bin2UrlBASE64(enc_node_key) + "\"}],\"i\":\"" + this._req_id + "\", \"cr\" : [ [\"" + root_node + "\"] , [\"xxxxxxxx\"] , [0,0, \"" + Bin2UrlBASE64(enc_node_key_s) + "\"]]}]";

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            res_map = objectMapper.readValue(res, HashMap[].class);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return res_map != null ? res_map[0] : null;

    }

    public String getPublicFileLink(final String node, final byte[] node_key) {

        String public_link = null;

        try {

            final String file_id;

            final List res_map;

            final String request = "[{\"a\":\"l\", \"n\":\"" + node + "\"}]";

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            res_map = objectMapper.readValue(res, List.class);

            file_id = (String) res_map.get(0);

            public_link = "https://mega.nz/#!" + file_id + "!" + Bin2UrlBASE64(node_key);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return public_link;
    }

    public String getPublicFolderLink(final String node, final byte[] node_key) {

        String public_link = null;

        try {

            final String folder_id;

            final List res_map;

            final String request = "[{\"a\":\"l\", \"n\":\"" + node + "\", \"i\":\"" + this._req_id + "\"}]";

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            final String res = this.RAW_REQUEST(request, url_api);

            final ObjectMapper objectMapper = new ObjectMapper();

            res_map = objectMapper.readValue(res, List.class);

            folder_id = (String) res_map.get(0);

            public_link = "https://mega.nz/#F!" + folder_id + "!" + Bin2UrlBASE64(node_key);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return public_link;
    }

    public int[] genUploadKey() {

        return bin2i32a(genRandomByteArray(24));
    }

    public byte[] genFolderKey() {

        return genRandomByteArray(16);
    }

    public byte[] genShareKey() {

        return genRandomByteArray(16);
    }

    public String shareFolder(final String node, final byte[] node_key, final byte[] share_key) {

        try {

            final String ok = Bin2UrlBASE64(this.encryptKey(share_key, i32a2bin(this.getMaster_key())));

            final String enc_nk = Bin2UrlBASE64(this.encryptKey(node_key, share_key));

            final String ha = this.cryptoHandleauth(node);

            //OJO
            final String request = "[{\"a\":\"s2\",\"n\":\"" + node + "\",\"s\":[{\"u\":\"EXP\",\"r\":0}],\"i\":\"" + this._req_id + "\",\"ok\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"ha\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"cr\":[[\"" + node + "\"],[\"" + node + "\"],[0,0,\"" + enc_nk + "\"]]}]";

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + (this._sid != null ? "&sid=" + this._sid : ""));

            return this.RAW_REQUEST(request, url_api);

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return null;
    }

    public String cryptoHandleauth(final String h) {

        String ch = null;

        try {

            ch = Bin2UrlBASE64(this.encryptKey((h + h).getBytes("UTF-8"), i32a2bin(this.getMaster_key())));

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return ch;
    }

    public boolean existsCachedFolderNodes(final String folder_id) {
        return Files.exists(Paths.get(System.getProperty("java.io.tmpdir") + File.separator + "megabasterd_folder_cache_" + folder_id));
    }

    private String getCachedFolderNodes(final String folder_id) {

        final String file_path = System.getProperty("java.io.tmpdir") + File.separator + "megabasterd_folder_cache_" + folder_id;

        if (Files.exists(Paths.get(file_path))) {

            LOG.log(Level.INFO, "MEGA FOLDER {0} USING CACHED JSON FILE TREE", new Object[]{folder_id});

            try {
                return new String(Files.readAllBytes(Paths.get(file_path)), "UTF-8");
            } catch (final IOException ex) {
                Logger.getLogger(MegaAPI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return null;
    }

    private void writeCachedFolderNodes(final String folder_id, final String res) {
        final String file_path = System.getProperty("java.io.tmpdir") + File.separator + "megabasterd_folder_cache_" + folder_id;

        try {
            Files.write(Paths.get(file_path), res.getBytes());
        } catch (final IOException ex) {
            Logger.getLogger(MegaAPI.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public HashMap<String, Object> getFolderNodes(final String folder_id, final String folder_key, final JProgressBar bar, final boolean cache) throws Exception {

        HashMap<String, Object> folder_nodes = null;

        String res = null;

        if (cache) {
            res = this.getCachedFolderNodes(folder_id);
        }

        if (res == null) {

            final String request = "[{\"a\":\"f\", \"c\":\"1\", \"r\":\"1\", \"ca\":\"1\"}]";

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + "&n=" + folder_id);

            res = this.RAW_REQUEST(request, url_api);

            if (res != null) {
                this.writeCachedFolderNodes(folder_id, res);
            }
        }

        LOG.log(Level.INFO, "MEGA FOLDER {0} JSON FILE TREE SIZE -> {1}", new Object[]{folder_id, MiscTools.formatBytes((long) res.length())});

        if (res != null) {

            final ObjectMapper objectMapper = new ObjectMapper();

            final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

            folder_nodes = new HashMap<>();

            final int s = ((List) res_map[0].get("f")).size();

            if (bar != null) {
                MiscTools.GUIRun(() -> {
                    bar.setIndeterminate(false);
                    bar.setMaximum(s);
                    bar.setValue(0);
                });
            }
            int conta_nodo = 0;

            for (final Object o : (Iterable<? extends Object>) res_map[0].get("f")) {

                conta_nodo++;

                final int c = conta_nodo;

                if (bar != null) {
                    MiscTools.GUIRun(() -> {

                        bar.setValue(c);
                    });
                }

                final HashMap<String, Object> node = (HashMap<String, Object>) o;

                final String[] node_k = ((String) node.get("k")).split(":");

                if (node_k.length == 2 && node_k[0] != "" && node_k[1] != "") {

                    try {

                        final String dec_node_k = Bin2UrlBASE64(this.decryptKey(UrlBASE642Bin(node_k[1]), this._urlBase64KeyDecode(folder_key)));

                        final HashMap at = this._decAttr((String) node.get("a"), this._urlBase64KeyDecode(dec_node_k));

                        final HashMap<String, Object> the_node = new HashMap<>();

                        the_node.put("type", node.get("t"));

                        the_node.put("parent", node.get("p"));

                        the_node.put("key", dec_node_k);

                        if (node.get("s") != null) {

                            if (node.get("s") instanceof Integer) {

                                final long size = ((Number) node.get("s")).longValue();
                                the_node.put("size", size);

                            } else if (node.get("s") instanceof Long) {

                                final long size = (Long) node.get("s");
                                the_node.put("size", size);
                            }
                        } else {
                            the_node.put("size", 0L);
                        }

                        the_node.put("name", at.get("n"));

                        the_node.put("h", node.get("h"));

                        folder_nodes.put((String) node.get("h"), the_node);

                    } catch (final Exception e) {
                        LOG.log(Level.WARNING, "WARNING: node key is not valid " + (String) node.get("k") + " " + folder_key);
                    }

                } else {
                    LOG.log(Level.WARNING, "WARNING: node key is not valid " + (String) node.get("k") + " " + folder_key);
                }

            }

        } else {

            throw new Exception();
        }

        return folder_nodes;
    }

    public ArrayList<String> GENERATE_N_LINKS(final Set<String> links) {

        final HashMap<String, ArrayList<String>> map = new HashMap<>();

        final ArrayList<String> nlinks = new ArrayList<>();

        for (final String link : links) {

            final String folder_id = findFirstRegex("#F\\*[^!]+!([^!]+)", link, 1);

            final String folder_key = findFirstRegex("#F\\*[^!]+![^!]+!([^!]+)", link, 1);

            final String file_id = findFirstRegex("#F\\*([^!]+)", link, 1);

            if (!map.containsKey(folder_id + ":" + folder_key)) {

                final ArrayList<String> lista = new ArrayList<>();

                lista.add(file_id);

                map.put(folder_id + ":" + folder_key, lista);

            } else {

                map.get(folder_id + ":" + folder_key).add(file_id);

            }
        }

        for (final Map.Entry<String, ArrayList<String>> entry : map.entrySet()) {

            final String[] folder_parts = entry.getKey().split(":");

            // Force not use cache version
            final int r = -1;

//            if (existsCachedFolderNodes(folder_parts[0])) {
//                r = JOptionPane.showConfirmDialog(MainPanelView.getINSTANCE(), "Do you want to use FOLDER [" + folder_parts[0] + "] CACHED VERSION?\n\n(It could speed up the loading of very large folders)", "FOLDER CACHE", JOptionPane.YES_NO_OPTION);
//            }

            try {
                nlinks.addAll(this.getNLinksFromFolder(folder_parts[0], folder_parts[1], entry.getValue(), (r == 0)));
            } catch (final Exception ex) {
                Logger.getLogger(MegaAPI.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

        return nlinks;

    }

    public ArrayList<String> getNLinksFromFolder(final String folder_id, final String folder_key, final ArrayList<String> file_ids, final boolean cache) throws Exception {

        final ArrayList<String> nlinks = new ArrayList<>();

        String res = null;

        if (cache) {
            res = this.getCachedFolderNodes(folder_id);
        }

        if (res == null) {

            final String request = "[{\"a\":\"f\", \"c\":\"1\", \"r\":\"1\", \"ca\":\"1\"}]";

            final URL url_api = new URL(API_URL + "/cs?id=" + String.valueOf(this._seqno) + "&n=" + folder_id);

            res = this.RAW_REQUEST(request, url_api);

            if (res != null) {
                this.writeCachedFolderNodes(folder_id, res);
            }
        }

        LOG.log(Level.INFO, "MEGA FOLDER {0} JSON FILE TREE SIZE -> {1}", new Object[]{folder_id, MiscTools.formatBytes((long) res.length())});

        if (res != null) {

            final ObjectMapper objectMapper = new ObjectMapper();

            final HashMap[] res_map = objectMapper.readValue(res, HashMap[].class);

            for (final Object o : (Iterable<? extends Object>) res_map[0].get("f")) {

                final HashMap<String, Object> node = (HashMap<String, Object>) o;

                final String[] node_k = ((String) node.get("k")).split(":");

                if (node_k.length == 2 && node_k[0] != "" && node_k[1] != "") {

                    try {

                        final String dec_node_k = Bin2UrlBASE64(this.decryptKey(UrlBASE642Bin(node_k[1]), this._urlBase64KeyDecode(folder_key)));

                        if (file_ids.contains((String) node.get("h"))) {

                            //Este es el que queremos
                            nlinks.add("https://mega.nz/#N!" + ((String) node.get("h")) + "!" + dec_node_k + "###n=" + folder_id);

                        }

                    } catch (final Exception e) {
                        LOG.log(Level.WARNING, "WARNING: node key is not valid " + (String) node.get("k") + " " + folder_key);
                    }

                } else {
                    LOG.log(Level.WARNING, "WARNING: node key is not valid " + (String) node.get("k") + " " + folder_key);
                }

            }

        } else {

            throw new Exception();
        }

        return nlinks;

    }

    private byte[] _urlBase64KeyDecode(final String key) {

        try {
            final byte[] key_bin = UrlBASE642Bin(key);

            if (key_bin.length < 32) {

                return Arrays.copyOfRange(key_bin, 0, 16);

            } else {

                final int[] key_i32a = bin2i32a(Arrays.copyOfRange(key_bin, 0, 32));

                final int[] k = {key_i32a[0] ^ key_i32a[4], key_i32a[1] ^ key_i32a[5], key_i32a[2] ^ key_i32a[6], key_i32a[3] ^ key_i32a[7]};

                return i32a2bin(k);
            }

        } catch (final Exception ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        }

        return null;
    }

}
