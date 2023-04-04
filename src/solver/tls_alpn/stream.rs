use super::error::Error;
use openssl::ssl::{ErrorCode, HandshakeError, MidHandshakeSslStream, SslAcceptor, SslStream};
use std::{
    fmt::{Debug, Formatter},
    future::Future,
    io::{self, ErrorKind, Read, Write},
    pin::Pin,
    ptr::null_mut,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub(crate) struct TlsAcceptor(SslAcceptor);

impl TlsAcceptor {
    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        handshake(move |s| self.0.accept(s), stream).await
    }
}

impl Debug for TlsAcceptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish()
    }
}

impl From<SslAcceptor> for TlsAcceptor {
    fn from(inner: SslAcceptor) -> Self {
        TlsAcceptor(inner)
    }
}

async fn handshake<F, S>(f: F, stream: S) -> Result<TlsStream<S>, Error>
where
    F: FnOnce(AllowStd<S>) -> Result<SslStream<AllowStd<S>>, HandshakeError<AllowStd<S>>> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = StartedHandshakeFuture(Some(StartedHandshakeFutureInner { f, stream }));

    match start.await {
        Err(e) => Err(e),
        Ok(StartedHandshake::Done(s)) => Ok(s),
        Ok(StartedHandshake::Mid(s)) => MidHandshake(Some(s)).await,
    }
}

enum StartedHandshake<S> {
    Done(TlsStream<S>),
    Mid(MidHandshakeTlsStream<S>),
}

struct StartedHandshakeFuture<F, S>(Option<StartedHandshakeFutureInner<F, S>>);
struct StartedHandshakeFutureInner<F, S> {
    f: F,
    stream: S,
}

impl<F, S> Future for StartedHandshakeFuture<F, S>
where
    F: FnOnce(AllowStd<S>) -> Result<SslStream<AllowStd<S>>, HandshakeError<AllowStd<S>>> + Unpin,
    S: Unpin,
    AllowStd<S>: Read + Write,
{
    type Output = Result<StartedHandshake<S>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.0.take().expect("future polled after completion");
        let stream = AllowStd {
            inner: inner.stream,
            context: cx as *mut _ as *mut (),
        };

        match (inner.f)(stream) {
            Ok(mut s) => {
                s.get_mut().context = null_mut();
                Poll::Ready(Ok(StartedHandshake::Done(TlsStream(s))))
            }
            Err(HandshakeError::SetupFailure(e)) => Poll::Ready(Err(e.into())),
            Err(HandshakeError::WouldBlock(mut s)) => {
                s.get_mut().context = null_mut();
                Poll::Ready(Ok(StartedHandshake::Mid(MidHandshakeTlsStream(s))))
            }
            Err(HandshakeError::Failure(e)) => {
                let v = e.ssl().verify_result();
                Poll::Ready(Err(Error::Ssl(e.into_error(), v)))
            }
        }
    }
}

struct MidHandshake<S>(Option<MidHandshakeTlsStream<S>>);

impl<S> Future for MidHandshake<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<TlsStream<S>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut_self = self.get_mut();
        let mut s = mut_self.0.take().expect("future polled after completion");

        s.get_mut().context = cx as *mut _ as *mut ();
        match s.handshake() {
            Ok(mut s) => {
                s.get_mut().get_mut().context = null_mut();
                Poll::Ready(Ok(s))
            }
            Err(HandshakeError::WouldBlock(mut s)) => {
                s.get_mut().context = null_mut();
                mut_self.0 = Some(MidHandshakeTlsStream(s));
                Poll::Pending
            }
            Err(HandshakeError::SetupFailure(e)) => Poll::Ready(Err(e.into())),
            Err(HandshakeError::Failure(e)) => {
                let v = e.ssl().verify_result();
                Poll::Ready(Err(Error::Ssl(e.into_error(), v)))
            }
        }
    }
}

struct MidHandshakeTlsStream<S>(MidHandshakeSslStream<AllowStd<S>>);

impl<S> Debug for MidHandshakeTlsStream<S>
where
    S: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<S> MidHandshakeTlsStream<S> {
    fn get_mut(&mut self) -> &mut AllowStd<S> {
        self.0.get_mut()
    }
}

impl<S> MidHandshakeTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
    AllowStd<S>: Read + Write,
{
    fn handshake(self) -> Result<TlsStream<S>, HandshakeError<AllowStd<S>>> {
        match self.0.handshake() {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TlsStream<S>(SslStream<AllowStd<S>>);

impl<S> TlsStream<S> {
    fn with_context<F, R>(&mut self, ctx: &mut Context<'_>, f: F) -> Poll<io::Result<R>>
    where
        F: FnOnce(&mut SslStream<AllowStd<S>>) -> io::Result<R>,
        AllowStd<S>: Read + Write,
    {
        self.0.get_mut().context = ctx as *mut _ as *mut ();
        let g = Guard(self);
        match f(&mut (g.0).0) {
            Ok(v) => Poll::Ready(Ok(v)),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn get_mut(&mut self) -> &mut SslStream<AllowStd<S>> {
        &mut self.0
    }

    pub(crate) fn get_ref(&self) -> &SslStream<AllowStd<S>> {
        &self.0
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| {
            let n = s.read(buf.initialize_unfilled())?;
            buf.advance(n);
            Ok(())
        })
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| s.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| s.flush())
    }

    // From https://github.com/sfackler/rust-native-tls/blob/8fa929d6c3fb7c7adfca9e0fdd6446f5dfb34f92/src/imp/openssl.rs#L455-L464
    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| match s.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(ErrorKind::Other, e))),
        })
    }
}

#[derive(Debug)]
pub(crate) struct AllowStd<S> {
    pub(crate) inner: S,
    pub(crate) context: *mut (),
}

// *mut () context is neither Send nor Sync
unsafe impl<S: Send> Send for AllowStd<S> {}
unsafe impl<S: Sync> Sync for AllowStd<S> {}

impl<S: Unpin> AllowStd<S> {
    pub(crate) fn with_context<F, R>(&mut self, f: F) -> io::Result<R>
    where
        F: FnOnce(&mut Context<'_>, Pin<&mut S>) -> Poll<io::Result<R>>,
    {
        unsafe {
            assert!(!self.context.is_null());
            let waker = &mut *(self.context as *mut _);
            match f(waker, Pin::new(&mut self.inner)) {
                Poll::Ready(r) => r,
                Poll::Pending => Err(io::Error::from(ErrorKind::WouldBlock)),
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S> Read for AllowStd<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        self.with_context(|ctx, stream| stream.poll_read(ctx, &mut buf))?;
        Ok(buf.filled().len())
    }
}

impl<S> Write for AllowStd<S>
where
    S: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.with_context(|ctx, stream| stream.poll_write(ctx, buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.with_context(|ctx, stream| stream.poll_flush(ctx))
    }
}

struct Guard<'a, S>(&'a mut TlsStream<S>)
where
    AllowStd<S>: Read + Write;

impl<S> Drop for Guard<'_, S>
where
    AllowStd<S>: Read + Write,
{
    fn drop(&mut self) {
        (self.0).0.get_mut().context = null_mut()
    }
}
