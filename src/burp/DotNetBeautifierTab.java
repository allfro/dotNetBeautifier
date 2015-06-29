package burp;

import java.awt.*;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by ndouba on 15-06-29.
 */
public class DotNetBeautifierTab implements IMessageEditorTab {

    private final IExtensionHelpers helpers;
    private final IMessageEditor messageEditor;
    private byte[] originalContent = null;
    private final HashMap<String, IParameter> parameterTracker = new HashMap<>();
    private final HashMap<String, Integer> nameTracker = new HashMap<>();

    public DotNetBeautifierTab(IBurpExtenderCallbacks callbacks, IMessageEditorController controller, boolean editable) {
        helpers = callbacks.getHelpers();
        messageEditor = callbacks.createMessageEditor(controller, editable);
    }

    @Override
    public String getTabCaption() {
        return "Beautify.NET";
    }

    @Override
    public Component getUiComponent() {
        return messageEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        if (isRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(content);
            for (IParameter parameter : requestInfo.getParameters()) {
                if (helpers.urlDecode(parameter.getName()).contains("$"))
                    return true;
            }
        }
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        messageEditor.setMessage(beautifyContent(content), isRequest);
    }

    private byte[] beautifyContent(byte[] content) {

        parameterTracker.clear();
        nameTracker.clear();

        if (content == null)
            return null;

        IRequestInfo requestInfo = helpers.analyzeRequest(content);
        byte[] newContent = Arrays.copyOf(content, content.length);


        for (IParameter parameter: requestInfo.getParameters()) {
            byte parameterType = parameter.getType();
            String parameterName = helpers.urlDecode(parameter.getName());
            String simplifiedParameterName;
            String parameterValue = null;

            if (parameterType != IParameter.PARAM_BODY
                    && parameterType != IParameter.PARAM_URL
                    && parameterType != IParameter.PARAM_MULTIPART_ATTR) {
                continue;
            }

            if (parameterName.contains("$")) {
                String[] fragments = parameterName.split("\\$");
                simplifiedParameterName = fragments[fragments.length - 1];
            } else if (parameterName.matches("^__(VIEWSTATE|PREVIOUSPAGE|EVENTVALIDATION)$")
                    && parameter.getValue().length() != 0) {
                simplifiedParameterName = parameterName;
                parameterValue = "<snipped>";
            } else {
                continue;
            }

            if (nameTracker.containsKey(simplifiedParameterName)) {
                int count = nameTracker.get(simplifiedParameterName);
                nameTracker.put(simplifiedParameterName, count + 1);
                simplifiedParameterName = String.format("%s[%d]", simplifiedParameterName, count);
            }

            nameTracker.putIfAbsent(simplifiedParameterName, 1);

            parameterTracker.put(simplifiedParameterName, parameter);

            newContent = helpers.removeParameter(newContent, parameter);
            newContent = helpers.addParameter(
                    newContent,
                    helpers.buildParameter(
                            helpers.urlEncode(simplifiedParameterName),
                            (parameterValue != null)?parameterValue:parameter.getValue(),
                            parameter.getType()
                    )
            );

        }

        return newContent;

    }

    private byte[] unbeautifyContent(byte[] content) {

        IRequestInfo requestInfo = helpers.analyzeRequest(content);
        byte[] newContent = content.clone();

        for (IParameter parameter: requestInfo.getParameters()) {
            String simplifiedParameterName = helpers.urlDecode(parameter.getName());
            if (parameterTracker.containsKey(simplifiedParameterName)) {
                IParameter originalParameter = parameterTracker.get(simplifiedParameterName);
                String parameterValue = parameter.getValue();
                newContent = helpers.removeParameter(newContent, parameter);
                newContent = helpers.addParameter(
                        newContent,
                        helpers.buildParameter(
                                originalParameter.getName(),
                                (parameterValue.equals("<snipped>")) ? originalParameter.getValue() : parameter.getValue(),
                                parameter.getType()
                        )
                );
            }
        }

        return newContent;

    }

    @Override
    public byte[] getMessage() {
        return (!isModified())?originalContent:unbeautifyContent(messageEditor.getMessage());
    }

    @Override
    public boolean isModified() {
        return messageEditor.isMessageModified();
    }

    @Override
    public byte[] getSelectedData() {
        return messageEditor.getSelectedData();
    }
}
