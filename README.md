# m3u8dc
a m3u8 downloader and decryptor


## downloader
### usage
downloader.exe [filepath]  
```
downloader.exe video.m3u8
```
this will downloads m3u8 clips from  
spcefied m3u8 filepath  


## decryptor
### usage
decryptor.exe [filerange:int]  
```
decryptor.exe 1248
```
this will decrypt files from 1.ts to 1248.ts  
and then merges them  
make sure both ```key.txt``` and ```iv.txt```  
exist in current workspace.  
they are array string begin with `[` and end with `]`  
like ```[85, 150, 74, 145, 54, 65, 245, 159, 123, 41, 152, 4, 250, 115, 126, 251]```