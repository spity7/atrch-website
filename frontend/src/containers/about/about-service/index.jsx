import { Link } from "react-router-dom";
import AboutData from "../../../data/global/about.json";

const AboutService = () => {
    return (
        <div className="service-area">
            <div className="container">
                <div className="row">
                    <div
                        className="col-lg-4 col-xl-5 offset-xl-1"
                        data-aos="fade-up"
                        data-aos-delay="300"
                    >
                        <h2 className="title">{AboutData[1].title}</h2>
                        <ul>
                            {AboutData[1].pagelinkText &&
                                AboutData[1].pagelinkText.map((single, key) => {
                                    return (
                                        <li key={key}>
                                            <Link
                                                to={
                                                    process.env.PUBLIC_URL + "/"
                                                }
                                            >
                                                {single}
                                            </Link>
                                        </li>
                                    );
                                })}
                        </ul>
                    </div>
                    <div
                        className="col-lg-8 col-xl-6 mb-sm-50 mb-md-70"
                        data-aos="fade-up"
                    >
                        <h2 className="title">{AboutData[0].title}</h2>
                        <p
                            dangerouslySetInnerHTML={{
                                __html: AboutData[0].excerpt,
                            }}
                        />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AboutService;
