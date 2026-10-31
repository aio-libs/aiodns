"""
Observe email-related TXT records; this is not email authentication validation.

Run with aiodns 4.x:
    python examples/email_dns_txt.py example.com --selector actual
Get the selector from DKIM-Signature or the sender's provider settings.
No selector is guessed; no SMTP connection or HTTP request is made.
"""

import argparse
import asyncio
import json

import pycares

import aiodns


async def observe_txt(resolver, owner, deadline=3.0):
    """Keep an empty answer, a DNS error, and a deadline distinguishable."""
    try:
        result = await asyncio.wait_for(
            resolver.query_dns(owner, 'TXT'), deadline
        )
    except asyncio.TimeoutError:
        return {'owner': owner, 'status': 'deadline', 'records': []}
    except aiodns.error.DNSError as error:
        return {
            'owner': owner,
            'status': 'dns_error',
            'error': list(error.args),
            'records': [],
        }

    records = []
    for record in result.answer:
        if record.type != pycares.QUERY_TYPE_TXT:
            continue  # A TXT response may also contain a CNAME answer.
        # pycares combines the character-strings within one TXT RR into data.
        # Separate TXT RRs must remain separate; do not join across records.
        value = record.data.data
        if isinstance(value, bytes):
            try:
                value = value.decode('ascii')
            except UnicodeDecodeError:
                records.append({'hex': value.hex(), 'ttl': record.ttl})
                continue
        records.append({'text': value, 'ttl': record.ttl})
    return {'owner': owner, 'status': 'answer', 'records': records}


async def main(domain, selector=None):
    domain = domain.rstrip('.').encode('idna').decode('ascii')
    owners = [domain + '.', '_dmarc.' + domain + '.']
    if selector:
        selector = selector.rstrip('.').encode('idna').decode('ascii')
        owners.append(selector + '._domainkey.' + domain + '.')
    # One resolver is reused for all queries. A short-lived CLI is one of the
    # cases where the async context manager gives useful deterministic cleanup.
    async with aiodns.DNSResolver() as resolver:
        observations = await asyncio.gather(
            *(observe_txt(resolver, owner) for owner in owners)
        )
    print(
        json.dumps(
            {
                'observations': observations,
                'dkim_selector_supplied': bool(selector),
            },
            indent=2,
        )
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'domain', help='Sender domain, not an email address or URL'
    )
    parser.add_argument(
        '--selector', help='Actual configured DKIM selector; omit to skip DKIM'
    )
    args = parser.parse_args()
    asyncio.run(main(args.domain, args.selector))
