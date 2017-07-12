# encoding: utf-8

import ckan.logic
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

_get_or_bust = ckan.logic.get_or_bust


def check_loaded_plugin(context,data_dict):

    pluginname = _get_or_bust(data_dict, 'name')

    #print "Hello Sunshine"
    ifaces = (eval('plugins.{}'.format(name)) for name in plugins.interfaces.__all__)
    implemented = [item.name
                    for iface in ifaces
                    for item in plugins.PluginImplementations(iface)]

    return pluginname in implemented
