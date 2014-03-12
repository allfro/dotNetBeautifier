from burp import (IBurpExtender, IProxyListener, IInterceptedProxyMessage, IParameter, IHttpListener,
                  IBurpExtenderCallbacks, IContextMenuFactory, IContextMenuInvocation)
from javax.swing import JMenuItem
from java.util import ArrayList

from urllib import unquote, quote
from urlparse import urlparse, urlunparse
import re

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, dotNetBeautifier  Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'


class BurpExtender(IBurpExtender, IProxyListener, IHttpListener, IContextMenuFactory):

    headerRegex = re.compile(r'X-dotNet-Beautifier:\s*(\d+(?:.\d+)?);')

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._tracker = {}
        self._counter = {}
        self._messageReference = float(0)

        callbacks.setExtensionName('.NET Beautifier')
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        if invocation.getToolFlag() not in [
            IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_PROXY,
            IBurpExtenderCallbacks.TOOL_INTRUDER
        ]:
            return

        if invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            return

        menuItemList = ArrayList()
        messageInfo = invocation.getSelectedMessages()[0]
        requestBytes = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        messageReference = self._getMessageReferenceFromBeautifyHeader(requestInfo, requestBytes)
        if messageReference != -1:
            def _unbeautifyClick(event):
                self._restoreParameters(messageReference, messageInfo)
            menuItemList.add(JMenuItem('Unbeautify Request', actionPerformed=_unbeautifyClick))
        else:
            self._messageReference += 1
            def _beautifyClick(event):
                self._simplifyParameters(self._messageReference, messageInfo)
            menuItemList.add(JMenuItem('Beautify Request', actionPerformed=_beautifyClick))
        return menuItemList

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            self.processRequestMessage(message)
        else:
            self.processResponseMessage(message)

    def processRequestMessage(self, interceptedMessage):
        messageReference = interceptedMessage.getMessageReference()
        if interceptedMessage.getMessageReference() not in self._tracker:
            self._simplifyParameters(messageReference, interceptedMessage.getMessageInfo())
            interceptedMessage.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK)
        else:
            self._restoreParameters(messageReference, interceptedMessage.getMessageInfo())
            interceptedMessage.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)

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
        headers.add('X-dotNet-Beautifier: %s; DO-NOT-REMOVE' % messageReference)
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

    def _getMessageReferenceFromBeautifyHeader(self, requestInfo, requestBytes):
        results = self.headerRegex.search(self._helpers.bytesToString(requestBytes[:requestInfo.getBodyOffset()]))
        if results:
            value = results.groups()[0]
            return float(value) if '.' in value else int(value)
        return -1

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or toolFlag == IBurpExtenderCallbacks.TOOL_PROXY:
            return

        requestBytes = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(requestBytes)

        messageReference = self._getMessageReferenceFromBeautifyHeader(requestInfo, requestBytes)
        if messageReference != -1:
            self._restoreParameters(messageReference, messageInfo)