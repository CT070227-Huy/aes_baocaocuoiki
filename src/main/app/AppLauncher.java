package app;

import ui.MainFrame;

import java.awt.EventQueue;

public class AppLauncher {
    public static void main(String[] args) {
        launch();
    }

    // Start the Swing application on the Event Dispatch Thread.
    public static void launch() {
        EventQueue.invokeLater(() -> {
            MainFrame mainFrame = new MainFrame();
            mainFrame.setVisible(true);
        });
    }
}
