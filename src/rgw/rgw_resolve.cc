// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "acconfig.h"

#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include "rgw_common.h"
#include "rgw_resolve.h"

#define dout_subsys ceph_subsys_rgw

class RGWDNSResolver {
  Mutex lock;


public:
  ~RGWDNSResolver();
  RGWDNSResolver() : lock("RGWDNSResolver") {}
  int resolve_cname(const string& hostname, string& cname, bool *found);
};

RGWDNSResolver::~RGWDNSResolver()
{
}


int RGWDNSResolver::resolve_cname(const string& hostname, string& cname, bool *found)
{
  *found = false;

  int ret;

#define LARGE_ENOUGH_DNS_BUFSIZE 1024
  unsigned char buf[LARGE_ENOUGH_DNS_BUFSIZE];

#define MAX_FQDN_SIZE 255
  char host[MAX_FQDN_SIZE + 1];
  const char *origname = hostname.c_str();
  unsigned char *pt, *answer;
  unsigned char *answend;
  int len = res_query(origname, C_IN, T_CNAME, buf, sizeof(buf));
  if (len < 0) {
    dout(20) << "res_query() failed" << dendl;
    ret = 0;
    goto done;
  }

  answer = buf;
  pt = answer + sizeof(HEADER);
  answend = answer + len;

  /* read query */
  if ((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
    dout(0) << "ERROR: dn_expand() failed" << dendl;
    ret = -EINVAL;
    goto done;
  }
  pt += len;

  if (pt + 4 > answend) {
    dout(0) << "ERROR: bad reply" << dendl;
    ret = -EIO;
    goto done;
  }

  int type;
  GETSHORT(type, pt);

  if (type != T_CNAME) {
    dout(0) << "ERROR: failed response type: type=%d (was expecting " << T_CNAME << ")" << dendl;
    ret = -EIO;
    goto done;
  }

  pt += INT16SZ; /* class */

  /* read answer */

  if ((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
    ret = 0;
    goto done;
  }
  pt += len;
  dout(20) << "name=" << host << dendl;

  if (pt + 10 > answend) {
    dout(0) << "ERROR: bad reply" << dendl;
    ret = -EIO;
    goto done;
  }

  GETSHORT(type, pt);
  pt += INT16SZ; /* class */
  pt += INT32SZ; /* ttl */
  pt += INT16SZ; /* size */

  if ((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
    ret = 0;
    goto done;
  }
  dout(20) << "cname host=" << host << dendl;
  cname = host;

  *found = true;
  ret = 0;
done:
  return ret;
}

RGWResolver::~RGWResolver() {
  delete resolver;
}
RGWResolver::RGWResolver() {
  resolver = new RGWDNSResolver;
}

int RGWResolver::resolve_cname(const string& hostname, string& cname, bool *found) {
  return resolver->resolve_cname(hostname, cname, found);
}

RGWResolver *rgw_resolver;


void rgw_init_resolver()
{
  rgw_resolver = new RGWResolver();
}

void rgw_shutdown_resolver()
{
  delete rgw_resolver;
}
