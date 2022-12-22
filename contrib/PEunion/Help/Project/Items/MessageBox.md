# Message Box

Displays a Message Box with the specified content. Click `Preview` to see the MessageBox.

## Events

A button click does nothing by default. However, it can be used to trigger specific actions:

* `Skip next action`: The next item of the project is not executed if the button was clicked
* `Exit`: The stub terminates if the button was clicked

**Example:**

```
Do you want to write "file.exe" to disk?
              [Yes] [No]
```

In this example, the next item is a `Drop` and the event of the No-button is set to `Skip next action`. The Yes-button is set to `Do nothing`.