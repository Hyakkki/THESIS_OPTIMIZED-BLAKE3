# -*- coding: utf-8 -*-
"""Legacy filename retained as a migration marker.

The active Autopsy ingest entry point is ``blake3_ingest_module.py``. This file
intentionally defines no IngestModuleFactoryAdapter subclass; keeping two
factories in the same plugin directory would hash every item twice and corrupt
performance measurements. The pre-v4 implementation remains in Git history.
"""
