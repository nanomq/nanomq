CC = gcc
CFLAGS = -Wall -g -fPIC
INC = -I./inlcude
OBJ = mqtt_db.o zmalloc.o hash.o 
DLIBS = -lnano
LDFLAGS = -L.
RPATH = -Wl,-rpath=.
DESTDIR = /usr/local/include/



all:nanolib test.c
	$(CC) -o nano test.c $(CFLAGS) $(LDFLAGS) $(DLIBS) $(RPATH) -lpthread # -fsanitize=thread -g -O1
	# ./nano
	valgrind ./nano

%.o:%.c $(INC) 
	$(CC)  -c -o $@ $< $(CFLAGS) 

hash.o:hash.cc
	g++ -c -o hash.o hash.cc -Wall -g -fPIC

nanolib:$(OBJ) 
	$(CC) -shared -fPIC -o libnano.so $(OBJ) -lstdc++ -lpthread
	rm -f $(OBJ) 

dbkiller:nanolib dbkiller.c
	$(CC) -o dbkiller dbkiller.c $(CFLAGS) $(LDFLAGS) -lnano -ldill -lpthread $(RPATH)

.PHONY:clean
clean:
	rm -f $(OBJ) libnano.so nano
