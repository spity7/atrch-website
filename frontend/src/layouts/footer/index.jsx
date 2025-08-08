import { Link } from "react-router-dom";
import FooterLogo from "../../components/footer-logo";

const Footer = () => {
    return (
        <footer className="footer-area reveal-footer border-top-style">
            <div className="container-fluid">
                <div className="row">
                    <div className="col-sm-12">
                        <div className="footer-content">
                            <div className="widget-item">
                                {/* <div className="widget-footer-nav">
                                    <nav>
                                        <ul>
                                            <li>
                                                <Link
                                                    to={
                                                        process.env.PUBLIC_URL +
                                                        "/"
                                                    }
                                                >
                                                    term &amp; condition
                                                </Link>
                                            </li>
                                            <li>
                                                <Link
                                                    to={
                                                        process.env.PUBLIC_URL +
                                                        "/"
                                                    }
                                                >
                                                    policy
                                                </Link>
                                            </li>
                                            <li>
                                                <Link
                                                    to={
                                                        process.env.PUBLIC_URL +
                                                        "/"
                                                    }
                                                >
                                                    map
                                                </Link>
                                            </li>
                                        </ul>
                                    </nav>
                                </div> */}
                            </div>
                            <div className="widget-item text-center">
                                <div className="about-widget">
                                    <FooterLogo
                                        image={`${process.env.PUBLIC_URL}/img/logo.png`}
                                    />
                                </div>
                                {/* <div className="widget-copyright">
                                    <p>
                                        © 2021 <span>Alexis</span>. Made with{" "}
                                        <i className="icofont-heart-alt"></i> by{" "}
                                        <a
                                            target="_blank"
                                            href="https://www.hasthemes.com"
                                            rel="noreferrer"
                                        >
                                            HasThemes
                                        </a>
                                    </p>
                                </div> */}
                            </div>
                            <div className="widget-item">
                                {/* <ul className="widget-social">
                                    <li className="social-text">
                                        <span>follow us on social</span>
                                    </li>
                                    <li>
                                        <a
                                            href="https://twitter.com/"
                                            target="_blank"
                                            rel="noopener noreferrer"
                                        >
                                            <i className="social_twitter"></i>
                                        </a>
                                    </li>
                                    <li>
                                        <a
                                            href="https://www.facebook.com/"
                                            target="_blank"
                                            rel="noopener noreferrer"
                                        >
                                            <i className="social_facebook"></i>
                                        </a>
                                    </li>
                                    <li>
                                        <a
                                            href="https://www.instagram.com/"
                                            target="_blank"
                                            rel="noopener noreferrer"
                                        >
                                            <i className="social_instagram"></i>
                                        </a>
                                    </li>
                                </ul> */}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
