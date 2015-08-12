skateboard
==========

This is where the research from Richo Healey and Mike Ryan's skateboard hacking
talk will be ending up.

boosted_repl.py
---------------

This file forms the basis of our boosted exploit. It's been nerfed to remove
support for driving the jammers, and to lack the autopwn functionality but is
otherwise functional. You'll need to install `gevent` and `pycrypto` from pip,
as well as [pybt][pybt] and [scapy][scapy] from source upstream.

Invoke the script as:

    sudo python boosted_repl.py <MAC>

And try some commands. Start with `soc`, `rc0` and `spin` :)

There's a help command to tell you what stuff is in there, regardless.

### Copyright

(C) 2015 Richo Healey and Mike Ryan

### License

See LICENSE, but tl;dr MIT.

[scapy]: https://bitbucket.org/secdev/scapy/wiki/Home
[pybt]: https://github.com/mikeryan/PyBT
