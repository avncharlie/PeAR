.PHONY: hook clean
all: driver

driver:
	gcc -c -fPIC aflpp_rewrite_driver.c
	ar rcs libPeARDriver.a aflpp_rewrite_driver.o
clean:
	rm *.a *.o
