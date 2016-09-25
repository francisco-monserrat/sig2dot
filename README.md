# sig2dot
Originally from http://www.chaosreigns.com/code/sig2dot/ , added some other options and some bad code ,
 use --help to check the differnet options, some of the included options

--all : Add the keys that has no other sigantures 
--allinvis : Add the keys, but put a "invis" style to the keys without signature 
--debug : Output debug information
--countsig : Put a label with the relation of signatures of the key (Signed by, signed to )


## Running
```
$ gpg --list-sigs | perl sig2dot.pl | circo -Tpng -osigs.png

### Movie option

$ gpg --list-sigs | perl sig2dot.pl --movie movie --sequence 

This generate different movie-XX.dot files with the evolution of the PGP signatures (when a key whas created a signature was created, etc)

 then use :

x_for i in `ls movie*dot`; do XXX -Tpng -O $i ; done 

where XXX is neato, circo, etc (prove different graph approach)

to generate the different graphs and use ffmpeg to render a movie

About the moving, I' dont know but the "style=invis" don't place the nodes in the same place , so the graphs are not equal

```
