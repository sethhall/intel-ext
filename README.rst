Bro Intel Framework Extensions (Bro v2.4)
=========================================

These are some extensions for Bro 2.4's Intel framework.

  - The ability to extend the Intel log with the 
    Intel::extend_match event.  This also disables the
    normal intel.log and creates a file named intel_ext.log.

  - The ability to whitelist items with the new intel
    item field named "whitelist".  To use it, create a new
    intel file with an additional field named "whitelist"
    using the value "T".  That will cause the item to be 
    a whitelisted item and avoid logging it.