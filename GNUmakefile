PROG_CXX   = testDes
SRCS_CXX   = main.cc
#SRCS       = des.c

CFLAGS     ?= -g -pthread -Wall -Wextra -I/usr/local/include
CXXFLAGS   ?= -g -std=c++98 -pedantic -pthread -Wall -Wextra -I/usr/local/include
LDFLAGS     = 

all: $(PROG_CXX)

clean:
	-rm $(PROG_CXX) $(SRCS_CXX:.cc=.o) $(SRCS:.c=.o)

$(PROG_CXX): $(SRCS_CXX:.cc=.o) $(SRCS:.c=.o)
	$(LINK.cc) $^ -o $@
