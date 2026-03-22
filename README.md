How to compile

```
# Compile
mkdir -p out
javac --release 21 -d out P2PCamera.java

# Run with defaults (30s, password WuZfSZHC)
java -cp out com.p2pcamera.P2PCamera

# Or with options
java -cp out com.p2pcamera.P2PCamera \
  --password WuZfSZHC \
  --duration 60 \
  --video cam.mjpeg \
  --audio cam.raw

# Play result
ffplay -f mjpeg stream.mjpeg
ffplay -f mulaw -ar 8000 -ac 1 stream.raw
ffmpeg -f mjpeg -i stream.mjpeg -f mulaw -ar 8000 -ac 1 -i stream.raw \
       -c:v libx264 -c:a aac output_av.mp4
```
