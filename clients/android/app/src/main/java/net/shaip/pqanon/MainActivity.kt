package net.shaip.pqanon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import net.shaip.pqanon.net.Api
import net.shaip.pqanon.net.Session
import net.shaip.pqanon.ui.PqAnonApp
import net.shaip.pqanon.ui.theme.PqAnonTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val session = Session(this)
        val api = Api(session)
        setContent {
            PqAnonTheme { PqAnonApp(api, session) }
        }
    }
}
