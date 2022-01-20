CC = gcc
CFLAGS = -Wall -g -fPIC
INC = -I./include
OBJ = mqtt_db.o zmalloc.o hash_table.o 
TEST = test.c test_hash.c test_dbtree.c
DLIBS = -lnano
LDFLAGS = -L.
RPATH = -Wl,-rpath=.
DESTDIR = /usr/local/include/



all:nanolib test.c
	$(CC) -o nano $(TEST) $(CFLAGS) $(LDFLAGS) $(DLIBS) $(RPATH) -lpthread # -fsanitize=thread -g -O1
	./nano

%.o:%.c $(INC) 
	$(CC)  -c -o $@ $< $(CFLAGS) 

hash.o:hash.cc
	g++ -c -o hash.o hash.cc -Wall -g -fPIC

nanolib:$(OBJ) 
	$(CC) -shared -fPIC -o libnano.so $(OBJ) -lpthread
	rm -f $(OBJ) 

dbkiller:nanolib dbkiller.c
	$(CC) -o dbkiller dbkiller.c $(CFLAGS) $(LDFLAGS) -lnano -ldill -lpthread $(RPATH)

check:nano
	valgrind ./nano
        
check-s:nano
	valgrind -s ./nano

.PHONY:clean
clean:
	rm -f $(OBJ) libnano.so nano
# DO NOT DELETE

zmalloc.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
