# sig2dot
Originally from http://www.chaosreigns.com/code/sig2dot/

## Running
```
$ gpg --list-sigs | perl sig2dot.pl | circo -Tpng -osigs.png

### Movie option

$ gpg --list-sigs | perl sig2dot.pl --movie movie --sequence 

This generate different movie-XX.dot files with the evolution of the PGP signatures (when a key whas created a signature was created, etc)

 then use :

for i in `ls movie*dot`; do circle -Tpng -O $i ; done 

to generate the different graphs and use ffmpeg to render a movie

```
