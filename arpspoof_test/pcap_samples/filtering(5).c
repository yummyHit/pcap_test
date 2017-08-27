    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without an address we suppose to be in a C class network */
        netmask=0xffffff; 


//compile the filter
    if (pcap_compile(adhandle, &fcode, "ip and tcp", 1, netmask) < 0)
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
//set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
