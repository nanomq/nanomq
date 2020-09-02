CC = gcc
CFLAGS = -Wall
DEPS = packet_parser.h
OBJ =  main.o packet_parser.o 

	
%.o:%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

nanomqlib:$(OBJ) 
	$(CC) -o nanolib $(OBJ) 
	rm -f $(OBJ) 

#$(CC) -o nanolib main.o packet_parser.o 
#$(CC) -o $@ $< 

.PHONY:clean
clean:
	rm -f $(OBJ) nanolib
