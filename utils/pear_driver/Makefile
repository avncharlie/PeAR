.PHONY: hook clean
all: driver

driver:
	gcc -c -fPIC pear_rewrite_driver.c
	ar rcs libPeARDriver.a pear_rewrite_driver.o
clean:
	rm *.a *.o
