#!/usr/sbin/dtrace -s
#pragma D option quiet


BEGIN{
    printf("exec pid  -> port\n");
}

syscall::bind:entry
{
    socks = (struct sockaddr*) copyin(arg1,arg2);
    hport = (uint16_t) socks->sa_data[0];
    lport = (uint16_t) socks->sa_data[1]; 
    hport <<= 8;
    lport &= 0x00ff;
    port = hport + lport;
    self->port = port;
    //printf("%s: %d.%d.%d.%d:%d\n", execname, socks->sa_data[2], socks->sa_data[3], socks->sa_data[4], socks->sa_data[5],port);
    
}

syscall::bind:return
/self->port != 0/
{
    printf("%s %d -> port:%d\n", execname, pid, self->port);
    self->port = 0;
}