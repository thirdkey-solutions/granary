(c) Third Key Solutions LLC

granary: A library and interactive shell for key generation, storage and recovery


INSTALL
=======

    $ cd granary
    $ virtualenv pyenv
    $ source pyenv/bin/activate

    (pyenv)$ python setup.py install

To test:

    (pyenv)$ python setup.py test

  
SHELL
=====

Run the granary-shell command for interactive use of the library
 
    (pyenv)$ granary-shell
    
    granary $ help
    
Run several shell commands together to build a complete workflow:

    $ granary-shell seeds generate_master seeds stretch_master seeds generate_seed seeds save_seed show_seed_xpub
    



