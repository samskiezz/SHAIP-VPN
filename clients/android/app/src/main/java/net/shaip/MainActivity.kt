package net.shaip

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import net.shaip.net.Api
import net.shaip.net.Session
import net.shaip.ui.ShaipApp
import net.shaip.ui.theme.ShaipTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val session = Session(this)
        val api = Api(session)
        setContent {
            ShaipTheme { ShaipApp(api, session) }
        }
    }
}
