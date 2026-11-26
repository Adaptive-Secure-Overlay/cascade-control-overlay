-keep class org.adaptivesecureoverlay.cco.NativeBridge { *; }
-keep class org.adaptivesecureoverlay.cco.CcoVpnService {
    public boolean protect(int);
}
