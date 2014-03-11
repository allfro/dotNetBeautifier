from burp import (IBurpExtender, IProxyListener, IInterceptedProxyMessage, IParameter, IHttpListener,
                  IBurpExtenderCallbacks)
from urllib import unquote, quote
import shelve
# import os
import re


class ShelfProxyDict(object):
    def __init__(self, filename, flag='c', protocol=None, writeback=False):
        self._shelve = shelve.DbfilenameShelf(filename, flag, protocol, writeback)

    def _stringifyKey(self, key):
        if not isinstance(key, str):
            return str(key)
        return key

    def __setitem__(self, key, value):
        self._shelve[self._stringifyKey(key)] = value

    def __getitem__(self, key):
        return self._shelve[self._stringifyKey(key)]

    def __delitem__(self, key):
        del self._shelve[self._stringifyKey(key)]

    def has_key(self, key):
        return self._shelve.has_key(self._stringifyKey(key))

    def __contains__(self, key):
        return self._shelve.has_key(self._stringifyKey(key))

    def __getattr__(self, item):
        return getattr(self._shelve, item)

    def __repr__(self):
        return repr(self._shelve)

    def __str__(self):
        return str(self._shelve)

    def __del__(self):
        del self._shelve


class BurpExtender(IBurpExtender, IProxyListener, IHttpListener):
    headerRegex = re.compile(r'X-dotNet-Beautifier:\s*(\d+);')

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._tracker = {} #ShelfProxyDict(os.path.join(os.path.expanduser('~'), '.dnb_tracker'), writeback=True)
        self._counter = {} #ShelfProxyDict(os.path.join(os.path.expanduser('~'), '.dnb_counter'), writeback=True)
        # self._headers = ShelfProxyDict(os.path.join(os.path.expanduser('~'), '.dnb_headers'), writeback=True)
        # self._stdout = callbacks.getStdout()
        # self._stderr = callbacks.getStderr()

        callbacks.setExtensionName('.NET Beautifier')
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            self.processRequestMessage(message)
        else:
            self.processResponseMessage(message)

    def processRequestMessage(self, message):
        messageReference = message.getMessageReference()
        if message.getMessageReference() not in self._tracker:

            # self._stdout.write('modifying request %d\n' % messageReference)
            # self._stdout.write('BEFORE MODIFICATION:\n')
            # self._stdout.write(message.getMessageInfo().getRequest())
            self._simplifyParameters(messageReference, message.getMessageInfo())
            # self._stdout.write('AFTER MODIFICATION:\n')
            # self._stdout.write(message.getMessageInfo().getRequest())
            message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK)
        else:
            # self._stdout.write('restoring request %d\n' % messageReference)
            # self._stdout.write('BEFORE RESTORATION:\n')
            # self._stdout.write(message.getMessageInfo().getRequest())
            self._restoreParameters(messageReference, message.getMessageInfo())
            # self._stdout.write('AFTER RESTORATION:\n')
            # self._stdout.write(message.getMessageInfo().getRequest())
            message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)
        self._syncShelves()

    def processResponseMessage(self, message):
        pass

    def _simplifyParameters(self, messageReference, messageInfo):
        requestBytes = self._addBeautifyHeader(messageReference, messageInfo.getRequest())
        requestInfo = self._helpers.analyzeRequest(requestBytes)

        self._tracker[messageReference] = {}

        for parameter in requestInfo.getParameters():
            if parameter.getType() not in [IParameter.PARAM_BODY, IParameter.PARAM_URL,
                                           IParameter.PARAM_MULTIPART_ATTR]:
                continue
            parameterName = parameter.getName()
            value = '<snipped out for sanity>'
            if '$' in unquote(parameterName):
                simplifiedParameterName = quote(unquote(parameterName).split('$')[-1])
                value = parameter.getValue()
            elif unquote(parameterName) in ['__VIEWSTATE', '__PREVIOUSPAGE', '__PREVIOUSPAGE', '__EVENTVALIDATION']:
                simplifiedParameterName = parameterName
            else:
                continue
            if simplifiedParameterName in self._tracker[messageReference]:
                if not messageReference in self._counter:
                    self._counter[messageReference] = {simplifiedParameterName: 0}
                self._counter[messageReference][simplifiedParameterName] += 1
                simplifiedParameterName = '%s[%d]' % (
                    simplifiedParameterName, self._counter[messageReference][simplifiedParameterName])
            self._tracker[messageReference][simplifiedParameterName] = parameter
            simplifiedParameter = self._helpers.buildParameter(simplifiedParameterName, value, parameter.getType())
            requestBytes = self._helpers.removeParameter(requestBytes, parameter)
            requestBytes = self._helpers.addParameter(requestBytes, simplifiedParameter)

        messageInfo.setRequest(requestBytes)

    def _removeBeautifyHeader(self, requestBytes):
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        headers = requestInfo.getHeaders()
        header = None
        for h in headers:
            if h.startswith('X-dotNet-Beautifier'):
                header = h
                break
        if header:
            headers.remove(header)
        return self._helpers.buildHttpMessage(headers, requestBytes[requestInfo.getBodyOffset():])

    def _addBeautifyHeader(self, messageReference, requestBytes):
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        headers = requestInfo.getHeaders()
        headers.add('X-dotNet-Beautifier: %d; DO-NOT-REMOVE' % messageReference)
        return self._helpers.buildHttpMessage(headers, requestBytes[requestInfo.getBodyOffset():])

    def _restoreParameters(self, messageReference, messageInfo):
        requestBytes = self._removeBeautifyHeader(messageInfo.getRequest())
        requestInfo = self._helpers.analyzeRequest(requestBytes)

        for simplifiedParameter in requestInfo.getParameters():
            if simplifiedParameter.getType() not in [IParameter.PARAM_BODY, IParameter.PARAM_URL,
                                                     IParameter.PARAM_MULTIPART_ATTR]:
                continue
            simplifiedParameterName = simplifiedParameter.getName()
            if simplifiedParameterName in self._tracker[messageReference]:
                originalParameter = self._tracker[messageReference][simplifiedParameterName]
                if simplifiedParameterName not in ['__VIEWSTATE', '__PREVIOUSPAGE', '__PREVIOUSPAGE',
                                                   '__EVENTVALIDATION']:
                    originalParameter = self._helpers.buildParameter(originalParameter.getName(),
                                                                     simplifiedParameter.getValue(),
                                                                     simplifiedParameter.getType())
                requestBytes = self._helpers.removeParameter(requestBytes, simplifiedParameter)
                requestBytes = self._helpers.addParameter(requestBytes, originalParameter)

        messageInfo.setRequest(requestBytes)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or toolFlag == IBurpExtenderCallbacks.TOOL_PROXY:
            return

        requestBytes = messageInfo.getRequest()
        request = self._helpers.analyzeRequest(requestBytes)

        results = self.headerRegex.search(self._helpers.bytesToString(requestBytes[:request.getBodyOffset()]))
        if results:
            self._restoreParameters(int(results.groups()[0]), messageInfo)

    def _syncShelves(self):
        return
        # self._tracker.sync()
        # self._counter.sync()
        # self._headers.sync()

    def __del__(self):
        return
        # self._tracker.close()
        # self._counter.close()
        # self._headers.close()