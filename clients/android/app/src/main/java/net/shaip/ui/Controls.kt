package net.shaip.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import net.shaip.ui.theme.Tokens

/** White, glowing primary button (mirrors the design's SSO/primary button). */
@Composable
fun PrimaryButton(text: String, enabled: Boolean = true, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.height(48.dp),
        shape = RoundedCornerShape(999.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.White,
            contentColor = Tokens.Bg2,
            disabledContainerColor = Color.White.copy(alpha = 0.4f),
            disabledContentColor = Tokens.Bg2.copy(alpha = 0.6f),
        ),
    ) { Text(text, fontWeight = FontWeight.SemiBold) }
}

/** Translucent glass (secondary) button. */
@Composable
fun GlassButton(text: String, enabled: Boolean = true, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(999.dp)
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .height(44.dp)
            .border(BorderStroke(1.dp, Tokens.Hairline), shape),
        shape = shape,
        colors = ButtonDefaults.buttonColors(
            containerColor = Color(0x14FFFFFF),
            contentColor = Tokens.Ink,
            disabledContainerColor = Color(0x0AFFFFFF),
            disabledContentColor = Tokens.Ink3,
        ),
    ) { Text(text, fontWeight = FontWeight.Medium) }
}

/** Dark glass input field matching the web `.field` recipe. */
@Composable
fun Field(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    modifier: Modifier = Modifier,
    mono: Boolean = false,
    password: Boolean = false,
    numeric: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier.fillMaxWidth(),
        placeholder = { Text(placeholder, color = Tokens.Ink3) },
        singleLine = true,
        textStyle = TextStyle(
            color = Tokens.Ink,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.SansSerif,
        ),
        visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(
            keyboardType = if (numeric) KeyboardType.Number else if (password) KeyboardType.Password else KeyboardType.Text,
        ),
        shape = RoundedCornerShape(12.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = Tokens.FieldFill,
            unfocusedContainerColor = Tokens.FieldFill,
            focusedBorderColor = Tokens.Signal.copy(alpha = 0.5f),
            unfocusedBorderColor = Tokens.Hairline,
            cursorColor = Tokens.Signal,
            focusedTextColor = Tokens.Ink,
            unfocusedTextColor = Tokens.Ink,
        ),
    )
}
