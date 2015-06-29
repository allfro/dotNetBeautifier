package burp;


/**
 * @author Nadeem Douba
 * @version 1.0
 * @since 2015-06-29
 */
public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        callbacks.setExtensionName(".NET Beautifier");
        callbacks.registerMessageEditorTabFactory(this);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new DotNetBeautifierTab(callbacks, controller, editable);
    }
}
