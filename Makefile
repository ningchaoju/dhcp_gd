all:main_package_limit_mac main_evp_crypt 


main_package_limit_mac:main_package_limit_mac.c libdhcp_gd.so
	gcc -o $@ $^ -lcrypto -L. -ldhcp_gd
main_evp_crypt:main_evp_crypt.c libdhcp_gd.so
	gcc -o $@ $^ -lcrypto -L. -ldhcp_gd

libdhcp_gd.so:dhcp_gd.c
	gcc -o $@ $^ -lcrypto -fPIC -shared
	rm -rf /usr/lib64/libdhcp_gd.so
	ln -s $(PWD)/libdhcp_gd.so /usr/lib64

clean:
	rm -rf main_package_limit_mac main_evp_md main_evp_crypt libdhcp_gd.so *~ *.swap /usr/lib64/libdhcp_gd.so

