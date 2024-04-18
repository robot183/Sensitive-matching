package burp;


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.PrintWriter;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.util.regex.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;



public  class BurpExtender extends AbstractTableModel  implements IBurpExtender, IHttpListener, IScannerCheck, IMessageEditorController, ITab  {

    public IBurpExtenderCallbacks callbacks;

    public IExtensionHelpers helpers;

    public    List<IParameter>  parameters ;

    public  JTextField textField_payload ;
    public JSplitPane RootPane ; //创建主面板
//声明一个，用于输出的对象
    public PrintWriter  stdout ;
    public String regexhae ="\"([a-zA-Z]:\\\\.*?)\"|\"([a-zA-Z]:/.*?)\"|\"(/(bin|dev|home|media|opt|root|sbin|sys|usr|boot|data|etc|lib|mnt|proc|run|srv|tmp|var)/.*?)\"";;


    private IMessageEditor requestViewer;

    private IMessageEditor responseViewer;

    private IHttpRequestResponse currentlyDisplayedItem;


    public final List<LogEntry> log = new ArrayList<LogEntry>();

    public Table logTable;
    public  String  paths ;
    public JTextArea textArea;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks =  callbacks ;
        this.helpers=callbacks.getHelpers();
        this.stdout=   new PrintWriter(callbacks.getStdout(),true);
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);
        callbacks.setExtensionName("Sensitive matching");
        callbacks.printOutput("Author:Mind\n微信公众号: Mind安全点滴\n");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                RootPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane  jSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JSplitPane  jSplitPane2= new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                logTable = new Table(BurpExtender.this);

                JButton Button  =  new JButton("输入regax") ;
                JButton Button2 = new JButton("清除记录");
                textField_payload  = new JTextField("输入你想使用的regex");//regex文本


                textArea = new JTextArea(paths);
                textArea.setEditable(false);
                textArea.setLineWrap(true);
                textArea.setWrapStyleWord(true);


                JPanel panel= new JPanel();
                panel.setLayout(new GridLayout(18, 1));
                panel.add(Button);
                panel.add(Button2);
                panel.add(textField_payload);
                panel.add(textArea);

                jSplitPane2.setLeftComponent(panel);

                JScrollPane scrollPane = new JScrollPane(logTable);//先创建对象在放进去
                jSplitPane.setLeftComponent(scrollPane);



                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());

                jSplitPane.setRightComponent(tabs);

                //整体分布
                RootPane.setLeftComponent(jSplitPane);
                RootPane.setRightComponent(jSplitPane2);
                RootPane.setDividerLocation(1000);

                BurpExtender.this.callbacks.customizeUiComponent(RootPane);
                BurpExtender.this.callbacks.customizeUiComponent(logTable);
                BurpExtender.this.callbacks.customizeUiComponent(scrollPane);
                BurpExtender.this.callbacks.customizeUiComponent(panel);
                BurpExtender.this.callbacks.customizeUiComponent(tabs);

                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);

                Button.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
//                        log.clear();
                        regexhae = textField_payload.getText();
                        stdout.println( regexhae);
                        BurpExtender.this.fireTableDataChanged();

                    }
                });

                Button2.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log.clear();
                        paths = null;
                        BurpExtender.this.fireTableDataChanged();

                    }
                });


            }
        });




    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {



        if( toolFlag == 64 || toolFlag == 4){

            byte[] responsebody;
            if (messageIsRequest) {
                stdout.println("是一个请求");
            } else {
                responsebody = messageInfo.getResponse();


//               stdout.println(responseString);
                InputStream  inputStream  = new ByteArrayInputStream(responsebody);


                // 使用ByteArrayOutputStream来收集响应数据
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024]; // 缓冲区大小可以根据需要调整
                int bytesRead;

                try {
                    // 循环读取输入流中的数据到缓冲区，然后写入ByteArrayOutputStream
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        byteArrayOutputStream.write(buffer, 0, bytesRead);
                    }

                    // 将ByteArrayOutputStream中的数据转换为字符串
                    String responseString = byteArrayOutputStream.toString(StandardCharsets.UTF_8.name());

                    // 现在你可以处理responseString了
                    // 例如，使用正则表达式匹配路径或其他内容


                    stdout.println("现在使用的表达式"+regexhae);
                    Pattern p = Pattern.compile(regexhae);
                    Matcher m = p.matcher(responseString);

                    while (m.find()) {
                        stdout.println("发现路径: " + m.group());
                        paths=m.group();
                        updateTextAreaWithPaths(textArea, paths);


                        IResponseInfo response = this.helpers.analyzeResponse(responsebody);

                        String statusCode = String.valueOf(response.getStatusCode());

                        LogEntry logEntry = new LogEntry(this.helpers.analyzeRequest(messageInfo).getUrl().toString(), statusCode, "", messageInfo);

                        //刷新第一个列表框
                        log.add(logEntry);

                        BurpExtender.this.fireTableDataChanged();// size的值，不固定时，通过刷新列表框，展示实时数据包

                    }

                } catch (IOException e) {
                    // 处理可能的IOException
                    e.printStackTrace();
                } finally {
                    try {
                        // 关闭输入流和输出流
                        inputStream.close();
                        byteArrayOutputStream.close();
                    } catch (IOException e) {
                        // 处理关闭流时的异常
                        e.printStackTrace();
                    }
                }



            }


                //读取插件数据包 响应包内容 burpsuite  messageInfo.getResponse()

//            byte[]   response  = messageInfo.getResponse();
                //对Response消息进行解体
//            IResponseInfo analyzeResponse = helpers.analyzeResponse(response);
                //获得执行的状态码
//            int statusCode=analyzeResponse.getStatusCode();
                //获得header参数
//            List<String> headers = analyzeResponse.getHeaders();


                // 将字节数组转换为字符串，这里假设响应内容使用UTF-8编码  直接转换为字符类型，遇到 较大的响应包无法处理，使用 InputStream ，分段读取，使用 ByteArrayInputStream 转换为InputStream
//                String responseString = new String(response, StandardCharsets.UTF_8);










           // 正则表达式，匹配Windows和Unix/Linux风格的绝对路径    养成好习惯让ai ，帮你书写正则表达式



//            ^([A-Za-z]:\\\\|\\/)[^\\s]*$  ai生成 的表达式成功了   复制粘贴表达式时，编辑器，自动增加了\\要手动删除




        }

    }



//展示 数据包详情

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public String getTabCaption() {
        return  "Sensitive matching" ;
    }

    @Override
    public Component getUiComponent() {
        return RootPane;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "result";
            default:
                return "";
        }
    }


    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return true;
    }


    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url;
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }



    // 用于描述一条请求记录的数据结构
    private static class LogEntry{
        final String url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(String url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }
    // 自定义table的changeSelection方法，将request\response展示在正确的窗口中
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }


        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    public static void updateTextAreaWithPaths(JTextArea textArea, String paths) {
        // 创建一个StringBuilder来构建文本内容
        StringBuilder sb = new StringBuilder();

            sb.append(paths).append("\n"); // 每个路径后添加换行符


        // 使用setText方法更新JTextArea的内容
        textArea.setText(sb.toString());
    }



}


